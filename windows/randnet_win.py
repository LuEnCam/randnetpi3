#!/usr/bin/env python3
"""randnet_win - the randnetpi3 dial-up bridge for Windows.

Answers a call from a Nintendo 64 with the NUS-029 modem cartridge on the PC's
own modem, authenticates it over PPP/CHAP, and gives it the same network view
randnetpi3.py gives it on Linux: Randnet names redirected, the browsing proxy
in the path, and optionally a TLS tunnel to the Randnet server.

What it needs:  Python 3.9+, pyserial, and a voice-capable modem with a COM
port (a USB modem, or a softmodem whose Windows driver provides one).
What it does not need: admin rights, drivers beyond the modem's own, pppd,
iptables, dnsmasq or stunnel. PPP, NAT, DNS and TLS all run in this process.

  python randnet_win.py --list-ports
  python randnet_win.py --probe --config randnet_win.conf
  python randnet_win.py --config randnet_win.conf
  python randnet_win.py --self-test
"""

import argparse
import base64
import configparser
import logging
import os
import re
import signal
import socket
import ssl
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(HERE)
for _path in (HERE, PARENT):
    if _path not in sys.path:
        sys.path.insert(0, _path)



XP_PYSERIAL_HELP = (
    "pyserial 3.1 and newer call CancelIoEx, which Windows XP does not have, "
    "so they cannot even be imported there. Use pyserial 3.0.1, the last "
    "version without it: put pyserial-3.0.1-py3-none-any.whl in the "
    "windows-xp folder (it ships there), or run "
    "C:\\Python34\\python.exe -m pip install pyserial==3.0.1")


def _forget_serial():
    for name in list(sys.modules):
        if name == "serial" or name.startswith("serial."):
            del sys.modules[name]


def _version_key(path):
    name = os.path.basename(path).split("-")[1] if "-" in os.path.basename(path) else ""
    return [int(part) if part.isdigit() else 0 for part in name.split(".")]


def add_bundled_wheels(directories):
    """Pick a pyserial that imports on this machine.

    pyserial is pure Python, so a .whl file (a zip) can go straight on
    sys.path. A wheel dropped next to the script wins over an installed
    copy, newest first, and any wheel or installed copy that fails to import
    is skipped. That is what makes Windows XP work: pyserial 3.5 fails there
    (CancelIoEx), 3.0.1 does not.

    Returns the wheel used, or None for the installed copy. Raises
    SystemExit when nothing imports for a reason other than "not installed".
    """
    import glob
    wheels = []
    for directory in directories:
        for wheel in glob.glob(os.path.join(directory, "pyserial-*.whl")):
            if wheel not in wheels:
                wheels.append(wheel)
    wheels.sort(key=_version_key, reverse=True)

    errors = []
    for wheel in wheels:
        sys.path.insert(0, wheel)
        _forget_serial()
        try:
            import serial  # noqa: F401
            import serial.tools.list_ports  # noqa: F401
            return wheel
        except Exception as exc:
            errors.append("%s: %s" % (os.path.basename(wheel), exc))
            sys.path.remove(wheel)
            _forget_serial()

    try:
        import serial  # noqa: F401
        import serial.tools.list_ports  # noqa: F401
        return None
    except ImportError as exc:
        if not errors:
            return None
        errors.append("installed copy: %s" % exc)
    except Exception as exc:
        errors.append("installed copy: %s" % exc)
    _forget_serial()
    message = "No usable pyserial:\n  " + "\n  ".join(errors)
    if any("CancelIoEx" in error for error in errors):
        message += "\n\n" + XP_PYSERIAL_HELP
    raise SystemExit(message)


# The folder of the script that was started is searched first, so the
# windows-xp launcher's own wheel is found before anything is imported.
_MAIN_DIR = os.path.dirname(os.path.abspath(sys.argv[0])) if sys.argv and sys.argv[0] else HERE
BUNDLED_WHEEL = add_bundled_wheels((_MAIN_DIR, HERE, PARENT))

import dnsserver  # noqa: E402
import modem as modem_mod  # noqa: E402
import netstack  # noqa: E402
import ppp  # noqa: E402

logger = logging.getLogger("randnet-win")

VERSION = "3.0-win1"

DEFAULTS = {
    "modem": {
        "device": "",
        "speed": "57600",
        "usb_id": "",
        "dial_tone": "yes",
        "dial_tone_wav": "",
        "voice_sample_mode": "1,8000",
        "voice_encoding": "auto",
        "init_commands": "",
        "flow_control": "none",
        "use_dcd": "yes",
        "answer_mode": "voice",
        "answer_rings": "1",
        "answer_delay": "8.0",
        "post_answer_delay": "5.0",
        "reconnect_delay": "5.0",
    },
    "ppp": {
        "local_ip": "192.168.164.1",
        "peer_ip": "192.168.164.2",
        "chap_client": "*",
        "chap_name": "Randnet",
        "chap_secret": "K1QU0K@N",
        "chap_secret_b64": "",
        "ms_dns": "",
        "lcp_echo_interval": "30",
        "lcp_echo_failure": "4",
    },
    "network": {
        "randnet_redirect": "host",
        "randnet_domain": "randnet.ne.jp",
        "randnet_hostnames": (
            "randnet.ne.jp, www.randnet.ne.jp, peach.randnet.ne.jp, "
            "dd.randnet.ne.jp, smtp.dd.randnet.ne.jp, pop.dd.randnet.ne.jp"
        ),
        "dns_redirect": "172.16.10.30, 172.16.10.31",
        "upstream_dns": "",
        "proxy_hosts": "172.16.10.40:8080, 172.16.10.41:8080",
        "proxy_target_port": "",
        "transparent_http": "yes",
        "transparent_http_port": "8080",
        "randnet_tls": "no",
        "randnet_tls_host": "",
        "randnet_tls_port": "443",
        "ca_file": "",
    },
    "proxy": {
        "enabled": "yes",
        "port": "8080",
        "max_bytes": "32768",
        "timeout": "20",
        "preserve_agent_for": "randnet.ne.jp",
        "user_agent": "",
        "rewrite_https": "yes",
        "http_first": "no",
        "insecure": "no",
    },
}

INTERNET_CHECK_HOSTS = ("1.1.1.1", "8.8.8.8", "208.67.222.222")

HOSTNAME_RE = re.compile(
    r"\A(?=.{1,253}\Z)"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?\Z"
)



CONFIG_PATH = [None]


def config_relative(path):
    """Relative paths in the config are relative to the config file."""
    if not path or os.path.isabs(path):
        return path
    base = (os.path.dirname(os.path.abspath(CONFIG_PATH[0]))
            if CONFIG_PATH[0] else os.getcwd())
    return os.path.join(base, path)


def load_config(path=None):
    CONFIG_PATH[0] = path
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_dict(DEFAULTS)
    if path:
        if not os.path.exists(path):
            raise SystemExit("config file not found: %s" % path)
        if not parser.read(path, encoding="utf-8"):
            raise SystemExit("could not parse config file: %s" % path)
        logger.info("Loaded config from %s", path)
    return parser


def parse_host_list(value):
    return [item.strip() for item in re.split(r"[,\s]+", value or "") if item.strip()]


def parse_addr_port(value):
    addr, _, port = value.rpartition(":")
    if not addr or not port.isdigit():
        raise ValueError("expected ADDR:PORT, got %r" % value)
    return addr, int(port)


def is_ipv4_literal(value):
    parts = (value or "").split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
        if len(part) > 1 and part[0] == "0":
            return False
    return True


def resolve_chap_secret(cfg):
    encoded = cfg.get("ppp", "chap_secret_b64", fallback="").strip()
    if encoded:
        try:
            return base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise SystemExit("ppp.chap_secret_b64 is not valid base64: %s" % exc)
    return cfg.get("ppp", "chap_secret")


def local_host_address():
    """This PC's address on its default-route interface."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        address = probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()
    return None if address.startswith("127.") or address == "0.0.0.0" else address


def local_addresses():
    found = {"127.0.0.1"}
    primary = local_host_address()
    if primary:
        found.add(primary)
    try:
        found.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    return found


def check_internet_connection(timeout=3):
    for host in INTERNET_CHECK_HOSTS:
        try:
            with socket.create_connection((host, 53), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def resolve_randnet_target(cfg):
    """Where the Randnet names point. Returns (address or None, note)."""
    setting = cfg.get("network", "randnet_redirect").strip()
    if setting.lower() in ("off", "no", "none", ""):
        return None, "redirect disabled"
    if setting.lower() == "host":
        address = local_host_address()
        return address, "this PC" if address else "this PC's address not found"
    if is_ipv4_literal(setting):
        return setting, "fixed address"
    if not HOSTNAME_RE.match(setting):
        logger.error("network.randnet_redirect is neither an address, a "
                     "hostname, 'host' nor 'off': %r", setting)
        return None, "unusable setting"
    try:
        address = dnsserver.resolve_a(setting)[0]
    except (OSError, IndexError) as exc:
        logger.error("could not resolve %s (%s); the Randnet names will not be "
                     "redirected", setting, exc)
        return None, "%s unresolved" % setting
    if address.startswith("127."):
        logger.error("%s resolves to loopback %s, which the console cannot "
                     "use", setting, address)
        return None, "loopback"
    return address, "%s resolved to %s" % (setting, address)


def tls_tunnel_host(cfg):
    explicit = cfg.get("network", "randnet_tls_host").strip()
    if explicit:
        return explicit
    setting = cfg.get("network", "randnet_redirect").strip()
    if setting.lower() in ("host", "off", "no", "none", ""):
        return ""
    return setting



def make_tls_context(cfg):
    """A verifying client context: Windows' certificate store, plus
    network.ca_file when set. An old Windows (XP) has a root store too old
    for today's certificates, so it needs a current CA bundle in ca_file."""
    context = ssl.create_default_context()
    ca_file = cfg.get("network", "ca_file").strip()
    if ca_file:
        ca_file = config_relative(ca_file)
        if not os.path.exists(ca_file):
            raise SystemExit(
                "network.ca_file %s does not exist. It is a bundle of trusted "
                "root certificates to download, not to create: on a modern "
                "PC, get cacert.pem from https://curl.se/ca/cacert.pem (page: "
                "https://curl.se/docs/caextract.html) and copy it to that "
                "path." % ca_file)
        context.load_verify_locations(cafile=ca_file)
        logger.info("Loaded CA certificates from %s", ca_file)
    return context


class Router(object):
    """The iptables rules of randnetpi3.py, as one decision per connection."""

    def __init__(self, cfg, server_ip, local_ip, own_addresses):
        self.local_ip = local_ip
        self.own = set(own_addresses or ())
        self.server_ip = server_ip
        override = cfg.get("network", "proxy_target_port").strip()
        self.proxy_hosts = {}
        for entry in parse_host_list(cfg.get("network", "proxy_hosts")):
            addr, port = parse_addr_port(entry)
            self.proxy_hosts[(addr, port)] = int(override) if override else port
        self.transparent = cfg.getboolean("network", "transparent_http")
        self.transparent_port = int(
            cfg.get("network", "transparent_http_port").strip() or "8080")
        self.dns_hosts = set(parse_host_list(cfg.get("network", "dns_redirect")))
        self.tls = cfg.getboolean("network", "randnet_tls")
        self.tls_host = tls_tunnel_host(cfg)
        self.tls_port = int(cfg.get("network", "randnet_tls_port").strip() or "443")
        if self.tls and not (self.tls_host and server_ip):
            logger.warning(
                "network.randnet_tls is on but the Randnet server's name or "
                "address is unknown, so its traffic stays in the clear")
            self.tls = False

    def __call__(self, dst, dport):
        T = netstack.Target
        if (dst, dport) in self.proxy_hosts:
            port = self.proxy_hosts[(dst, dport)]
            return T("tcp", "127.0.0.1", port, "browsing proxy :%d" % port)
        if dport == 53 and dst in self.dns_hosts | {self.local_ip}:
            return T("refuse", None, None, "DNS over TCP is not served")
        if self.tls and dst == self.server_ip and dport == 80:
            return T("tls", self.tls_host, self.tls_port,
                     "TLS tunnel to %s:%d" % (self.tls_host, self.tls_port))
        if dst == self.local_ip:
            return T("tcp", "127.0.0.1", dport, "this PC")
        if dst in self.own:
            return T("tcp", dst, dport, "this PC")
        if self.transparent and dport == 80 and dst != self.server_ip:
            return T("tcp", "127.0.0.1", self.transparent_port,
                     "browsing proxy :%d" % self.transparent_port)
        return T("tcp", dst, dport, "direct")

    def describe(self):
        lines = []
        for (addr, port), target in sorted(self.proxy_hosts.items()):
            lines.append("tcp %s:%d -> 127.0.0.1:%d (browsing proxy)" % (addr, port, target))
        for host in sorted(self.dns_hosts | {self.local_ip}):
            lines.append("udp %s:53 -> built-in DNS" % host)
        if self.tls:
            lines.append("tcp %s:80 -> TLS %s:%d" % (self.server_ip, self.tls_host,
                                                    self.tls_port))
        lines.append("tcp %s:* -> 127.0.0.1:* (this PC)" % self.local_ip)
        if self.transparent:
            lines.append("tcp *:80%s -> 127.0.0.1:%d (browsing proxy)" % (
                " except %s" % self.server_ip if self.server_ip else "",
                self.transparent_port))
        lines.append("everything else -> direct")
        return lines



_ORIGINAL_GETADDRINFO = socket.getaddrinfo


def install_name_override(names, domain, address):
    """Make this process resolve the Randnet names to the server.

    The Linux bridge writes them into /etc/hosts so its proxy can resolve
    them. The proxy runs inside this process here, so a resolver hook does the
    same without touching the Windows hosts file or needing admin rights.
    """
    wanted = set(n.lower().rstrip(".") for n in names)
    domain = (domain or "").lower().strip(".")

    def matches(host):
        if not isinstance(host, str):
            return False
        host = host.lower().rstrip(".")
        return host in wanted or (domain and (host == domain or host.endswith("." + domain)))

    def getaddrinfo(host, *args, **kwargs):
        if address and matches(host):
            host = address
        return _ORIGINAL_GETADDRINFO(host, *args, **kwargs)

    socket.getaddrinfo = getaddrinfo


def start_proxy(cfg, own_names):
    if not cfg.getboolean("proxy", "enabled"):
        logger.info("Browsing proxy disabled in the config")
        return None
    try:
        import randnet_proxy
    except ImportError:
        raise SystemExit(
            "randnet_proxy.py was not found. It is not part of this folder: it "
            "is the browsing proxy from the main randnetpi3 folder, and the "
            "console's web traffic and the disk's proxy addresses go through "
            "it. Copy randnet_proxy.py next to randnet_win.py (%s) or into "
            "the folder above it (%s). To run without it on purpose, set "
            "enabled = no in [proxy]." % (HERE, PARENT))
    port = cfg.getint("proxy", "port")
    context = make_tls_context(cfg)
    if cfg.getboolean("proxy", "insecure"):
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        logger.warning("proxy: TLS certificate verification is DISABLED")

    class Server(randnet_proxy.ProxyServer):
        allow_reuse_address = os.name != "nt"

    Server.max_bytes = cfg.getint("proxy", "max_bytes")
    Server.upstream_timeout = cfg.getfloat("proxy", "timeout")
    Server.ssl_context = context
    agent = cfg.get("proxy", "user_agent").strip()
    if agent:
        Server.user_agent = agent
    Server.rewrite_https = cfg.getboolean("proxy", "rewrite_https")
    Server.https_first = not cfg.getboolean("proxy", "http_first")
    Server.listen_port = port
    Server.local_names = frozenset(set(randnet_proxy.local_names()) | own_names)
    Server.preserve_agent_for = tuple(
        parse_host_list(cfg.get("proxy", "preserve_agent_for")))

    try:
        server = Server(("127.0.0.1", port), randnet_proxy.ProxyHandler)
    except OSError as exc:
        logger.warning("Browsing proxy could not listen on 127.0.0.1:%d (%s). "
                       "If another copy of randnet_proxy.py is already running "
                       "there it will be used.", port, exc)
        return None
    thread = threading.Thread(target=server.serve_forever, name="randnet-proxy",
                              daemon=True)
    thread.start()
    logger.info("Browsing proxy listening on 127.0.0.1:%d (loopback only)", port)
    return server



class SocketLink(object):
    """A TCP connection that stands in for the modem, for testing with pppd."""

    def __init__(self, sock):
        self.sock = sock
        self.sock.setblocking(False)
        self.closed = False

    def write(self, data):
        view = memoryview(data)
        while view:
            try:
                sent = self.sock.send(view)
                view = view[sent:]
            except BlockingIOError:
                time.sleep(0.001)

    def read_available(self):
        try:
            data = self.sock.recv(65536)
        except BlockingIOError:
            return b""
        except OSError:
            self.closed = True
            return b""
        if not data:
            self.closed = True
        return data

    @property
    def carrier(self):
        return not self.closed


class Stopper(object):
    def __init__(self):
        self.stop = False
        signal.signal(signal.SIGINT, self._handle)
        for name in ("SIGTERM", "SIGBREAK"):
            if hasattr(signal, name):
                signal.signal(getattr(signal, name), self._handle)

    def _handle(self, signum, _frame):
        if self.stop:
            raise KeyboardInterrupt
        logger.warning("Stopping (signal %s); press Ctrl+C again to force", signum)
        self.stop = True


class Bridge(object):
    """Everything that lasts longer than one call."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.local_ip = cfg.get("ppp", "local_ip").strip()
        self.peer_ip = cfg.get("ppp", "peer_ip").strip()
        for key, value in (("local_ip", self.local_ip), ("peer_ip", self.peer_ip)):
            if not is_ipv4_literal(value):
                raise SystemExit("ppp.%s must be an IPv4 address, got %r" % (key, value))
        self.dns_ips = parse_host_list(cfg.get("ppp", "ms_dns")) or [self.local_ip]
        self.secret = resolve_chap_secret(cfg)
        self.server_ip, note = resolve_randnet_target(cfg)
        logger.info("Randnet names -> %s (%s)", self.server_ip or "not redirected", note)
        self.own = local_addresses()
        self.router = Router(cfg, self.server_ip, self.local_ip, self.own)
        self.hostnames = parse_host_list(cfg.get("network", "randnet_hostnames"))
        self.domain = cfg.get("network", "randnet_domain").strip()
        self.upstream_dns = cfg.get("network", "upstream_dns").strip() or None
        self.tls_context = make_tls_context(cfg)
        # TLS 1.2 minimum, spelled with option flags so Python 3.4 (the last
        # release for Windows XP) understands it too.
        for name in ("OP_NO_SSLv2", "OP_NO_SSLv3", "OP_NO_TLSv1", "OP_NO_TLSv1_1"):
            self.tls_context.options |= getattr(ssl, name, 0)

    def run_session(self, link, stopper, use_dcd=False):
        """One PPP session on an already connected line. Returns a reason."""
        state = {}

        def on_ip(packet):
            state["stack"].handle_packet(packet)

        session = ppp.PppServer(
            send_raw=link.write, on_ip=on_ip,
            local_ip=self.local_ip, peer_ip=self.peer_ip, dns_ips=self.dns_ips,
            chap_name=self.cfg.get("ppp", "chap_name"), chap_secret=self.secret,
            chap_client=self.cfg.get("ppp", "chap_client").strip(),
            echo_interval=self.cfg.getfloat("ppp", "lcp_echo_interval"),
            echo_failure=self.cfg.getint("ppp", "lcp_echo_failure"))
        stack = netstack.NatStack(
            self.local_ip, self.peer_ip, session.send_ip, self.router,
            dns_hosts=self.router.dns_hosts | set(self.dns_ips),
            tls_context=self.tls_context)
        stack.dns = dnsserver.DnsResponder(
            self.hostnames, self.domain, self.server_ip, stack.results,
            stack.submit, upstream=self.upstream_dns)
        state["stack"] = stack

        carrier_seen = False
        tail = b""
        reason = "stopped"
        started = time.monotonic()
        session.start()
        try:
            while not stopper.stop:
                data = link.read_available()
                if data:
                    session.feed(data)
                    # The modem's own result code once it has dropped back to
                    # command mode. The trailing CR keeps a page that merely
                    # mentions the words from matching.
                    tail = (tail + data)[-32:]
                    if b"NO CARRIER\r" in tail:
                        reason = "modem reported NO CARRIER"
                        break
                carrier = link.carrier
                if carrier:
                    carrier_seen = True
                elif carrier_seen and use_dcd:
                    reason = "carrier lost"
                    break
                elif getattr(link, "closed", False):
                    reason = "link closed"
                    break
                session.poll()
                if session.dead:
                    reason = session.dead_reason
                    break
                stack.mtu = min(session.peer_mru, 1500)
                stack.poll(0 if data else 0.005)
        finally:
            if not session.dead and not getattr(link, "closed", False):
                try:
                    session.terminate(reason)
                except Exception:
                    pass
            stack.close_all()
            logger.info(
                "Session over after %ds: %s (IP packets in %d, out %d; frames "
                "good %d, bad FCS %d)", time.monotonic() - started, reason,
                session.stats["rx_ip"], session.stats["tx_ip"],
                session.decoder.good, session.decoder.bad_fcs)
        return reason



def list_ports(cfg=None):
    """Every port the bridge would consider, and whether it answers AT."""
    try:
        import serial.tools.list_ports
    except ImportError:
        print("pyserial is not installed:  py -m pip install pyserial==3.5")
        return 1
    ports = sorted(serial.tools.list_ports.comports(), key=lambda p: p.device)
    modems = windows_modems()
    candidates = port_candidates(
        modems, [(p.device, p.description or "") for p in ports],
        windows_serialcomm())
    if not candidates:
        print("No serial ports or modems found. Check Device Manager > Modems, "
              "and that the modem's driver is installed.")
        return 1
    speed = cfg.getint("modem", "speed") if cfg else 57600
    modem_ports = set(p.upper() for p, _ in modems)
    print("%-8s %-9s %-11s %s" % ("PORT", "AT -> OK", "KIND", "NAME"))
    for device, label in candidates:
        kind = "modem" if device.upper() in modem_ports else "serial port"
        print("%-8s %-9s %-11s %s" % (device, "yes" if answers_at(device, speed)
                                      else "no", kind, label))
    print("\nThe modem is the port with AT -> OK. Set it as modem.device.")
    return 0


MODEM_CLASS_KEY = (r"SYSTEM\CurrentControlSet\Control\Class"
                   r"\{4D36E96D-E325-11CE-BFC1-08002BE10318}")


def _registry_values(key):
    values = {}
    index = 0
    while True:
        try:
            name, value, _ = winreg_mod().EnumValue(key, index)
        except OSError:
            return values
        values[name] = value
        index += 1


def winreg_mod():
    import winreg
    return winreg


def windows_modems():
    """Modems Windows has installed, as [(COM port, name)].

    Read from the Modem device class in the registry: the same list as
    Control Panel > Phone and Modem Options > Modems, with its "Attached To"
    port. pyserial 3.0.1 enumerates only the "Ports" class, so a softmodem
    (an internal RJ11 port) never shows up in its list.
    """
    if os.name != "nt":
        return []
    try:
        winreg = winreg_mod()
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, MODEM_CLASS_KEY)
    except OSError:
        return []
    found = []
    index = 0
    while True:
        try:
            sub = winreg.EnumKey(root, index)
        except OSError:
            break
        index += 1
        try:
            values = _registry_values(winreg.OpenKey(root, sub))
        except OSError:
            continue
        port = str(values.get("AttachedTo") or "").strip()
        name = str(values.get("FriendlyName") or values.get("DriverDesc") or "modem")
        if port.upper().startswith("COM") and port not in [p for p, _ in found]:
            found.append((port, name))
    return found


def windows_serialcomm():
    """Every COM port name the drivers registered, including softmodems'."""
    if os.name != "nt":
        return []
    try:
        winreg = winreg_mod()
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\SERIALCOMM")
    except OSError:
        return []
    return [(str(port), str(device))
            for device, port in sorted(_registry_values(key).items())]


def port_candidates(registry_modems, pyserial_ports, serialcomm):
    """Ports to try, most likely modem first, each once.

    registry_modems  [(port, name)] from the Modem device class
    pyserial_ports   [(port, description)] from serial.tools.list_ports
    serialcomm       [(port, driver device)] from SERIALCOMM
    """
    ordered = []
    seen = set()

    def add(port, label):
        key = port.upper()
        if key not in seen:
            seen.add(key)
            ordered.append((port, label))

    for port, name in registry_modems:
        add(port, name)
    for port, description in pyserial_ports:
        if "modem" in (description or "").lower() or "ttyACM" in port:
            add(port, description)
    for port, device in serialcomm:
        # \Device\Serial0 is a motherboard UART; anything else is a driver's
        # virtual port, which on an old PC usually means a modem.
        if not device.lower().startswith(r"\device\serial"):
            add(port, device)
    for port, description in pyserial_ports:
        add(port, description)
    for port, device in serialcomm:
        add(port, device)
    return ordered


def answers_at(device, speed, timeout=2.0):
    """True when something on the port replies OK to AT."""
    import serial
    try:
        port = serial.Serial(device, speed, timeout=0)
    except Exception as exc:
        logger.debug("%s: cannot open (%s)", device, exc)
        return False
    try:
        port.write(b"AT\r")
        deadline = time.time() + timeout
        buffered = b""
        while time.time() < deadline:
            waiting = port.in_waiting
            if waiting:
                buffered += port.read(waiting)
                if b"OK" in buffered:
                    return True
            else:
                time.sleep(0.05)
        logger.debug("%s: no OK to AT (got %r)", device, buffered[-40:])
        return False
    except Exception as exc:
        logger.debug("%s: AT probe failed (%s)", device, exc)
        return False
    finally:
        try:
            port.close()
        except Exception:
            pass


def detect_device(cfg):
    configured = cfg.get("modem", "device").strip()
    if configured:
        return configured
    try:
        import serial.tools.list_ports
    except ImportError:
        raise SystemExit("pyserial is not installed:  py -m pip install pyserial==3.5")
    ports = sorted(serial.tools.list_ports.comports(), key=lambda p: p.device)
    usb_id = cfg.get("modem", "usb_id").strip().lower()
    if not usb_id:
        candidates = port_candidates(
            windows_modems(),
            [(p.device, p.description or "") for p in ports],
            windows_serialcomm())
        speed = cfg.getint("modem", "speed")
        for device, label in candidates:
            if answers_at(device, speed):
                logger.info("Auto-detected %s (%s): it answers AT", device, label)
                return device
        if candidates:
            logger.warning(
                "No port answered AT. Tried: %s. Set modem.device to the "
                "modem's port (Control Panel > Phone and Modem Options > "
                "Modems > Attached To).",
                ", ".join("%s (%s)" % c for c in candidates))
        return None
    usb_id = cfg.get("modem", "usb_id").strip().lower()
    if usb_id:
        try:
            vid, pid = (int(part, 16) for part in usb_id.split(":", 1))
        except ValueError:
            raise SystemExit("usb_id must look like 0572:1329, got %r" % usb_id)
        for port in ports:
            if port.vid == vid and port.pid == pid:
                logger.info("Matched %s by USB id %s", port.device, usb_id)
                return port.device
        return None
    return None


def build_modem(cfg, device, args):
    wav = config_relative(cfg.get("modem", "dial_tone_wav").strip())
    if not cfg.getboolean("modem", "dial_tone") or args.disable_dial_tone:
        logger.info("Dial tone off: the line will be silent, but the modem stays "
                    "in voice mode so it can still hear the console dial")
        samples = b"\x80" * 8000
    elif wav:
        samples = modem_mod.read_wav_samples(wav)
        logger.info("Loaded %d bytes of dial tone from %s", len(samples), wav)
    else:
        samples = modem_mod.synthesize_dial_tone()
    init = [line.strip() for line in cfg.get("modem", "init_commands").splitlines()]
    flow = cfg.get("modem", "flow_control").strip().lower()
    if flow not in ("none", "rtscts"):
        raise SystemExit("modem.flow_control must be none or rtscts, got %r" % flow)
    try:
        return modem_mod.Modem(
            device, cfg.getint("modem", "speed"), samples,
            sample_mode=cfg.get("modem", "voice_sample_mode").strip(),
            init_commands=init, rtscts=(flow == "rtscts"),
            encoding=cfg.get("modem", "voice_encoding").strip())
    except ValueError as exc:
        raise SystemExit("modem: %s" % exc)


def probe_modem(cfg, args):
    device = detect_device(cfg)
    if not device:
        print("No modem found. Set modem.device, or see --list-ports.")
        return 1
    line = build_modem(cfg, device, args)
    line.open()
    print("Modem on %s\n" % device)
    replies = {}
    try:
        for command in ("ATZ0", "ATE0", "ATI", "ATI3", "AT+GMI", "AT+GMM",
                        "AT+FCLASS=?", "AT+FCLASS=8", "AT+VLS=?", "AT+VSM=?",
                        "AT+FCLASS=0"):
            reply = line.query(command)
            replies[command] = reply
            print("%-12s %s" % (command, " | ".join(
                part.strip() for part in reply.splitlines() if part.strip())
                or "(no answer)"))
    finally:
        line.close()
    ok, verdict, settings = modem_mod.analyse_probe(replies)
    print()
    for text in verdict:
        print(text)
    if ok and settings:
        print("\nPut in [modem]:")
        for key in ("voice_sample_mode", "voice_encoding"):
            print("  %s = %s" % (key, settings[key]))
    return 0 if ok else 1


def serve(cfg, args, stopper):
    bridge = Bridge(cfg)
    if bridge.server_ip:
        install_name_override(bridge.hostnames, bridge.domain, bridge.server_ip)
    proxy = start_proxy(cfg, bridge.own)
    for line in bridge.router.describe():
        logger.info("route: %s", line)

    if args.test_listen:
        return serve_test_listener(bridge, args.test_listen, stopper, proxy)

    while not stopper.stop:
        online = check_internet_connection()
        device = detect_device(cfg)
        if online and device:
            break
        if not online:
            logger.warning("No internet connection yet, waiting")
        if not device:
            logger.warning("No modem found, waiting (set modem.device, or see "
                           "--list-ports)")
        time.sleep(5)
    if stopper.stop:
        return 0

    answer_delay = cfg.getfloat("modem", "answer_delay")
    post_answer_delay = cfg.getfloat("modem", "post_answer_delay")
    reconnect_delay = cfg.getfloat("modem", "reconnect_delay")
    use_dcd = cfg.getboolean("modem", "use_dcd")
    answer_mode = cfg.get("modem", "answer_mode").strip().lower()
    if answer_mode not in ("voice", "ring"):
        raise SystemExit("modem.answer_mode must be voice or ring, got %r"
                         % answer_mode)
    answer_rings = max(1, cfg.getint("modem", "answer_rings"))
    if answer_mode == "ring":
        logger.info("Answer mode: ring. No dial tone is played here; the line "
                    "simulator must supply it and ring this modem.")
    line = build_modem(cfg, device, args)

    try:
        while not stopper.stop:
            try:
                if not line.is_open:
                    line.open()
                if answer_mode == "ring":
                    if not line.wait_for_ring(lambda: stopper.stop, answer_rings):
                        break
                else:
                    line.start_dial_tone()
                    digit = None
                    while not stopper.stop and digit is None:
                        sent = line.pump_dial_tone()
                        raw = line.read_byte()
                        if not raw:
                            if not sent:
                                time.sleep(0.005)
                            continue
                        if raw[0] != modem_mod.DLE:
                            continue
                        digit = modem_mod.decode_dtmf(line.read_byte())
                    if stopper.stop:
                        break
                    logger.info("Heard DTMF digit %s, taking the line off dial tone", digit)
                    line.stop_dial_tone()
                    deadline = time.monotonic() + answer_delay
                    while not stopper.stop and time.monotonic() < deadline:
                        time.sleep(0.1)
                    if stopper.stop:
                        break
                line.answer()
                time.sleep(post_answer_delay)
                logger.info("Starting PPP; the console will be %s", bridge.peer_ip)
                bridge.run_session(line, stopper, use_dcd=use_dcd)
                line.hang_up()
            except Exception as exc:
                logger.error("Modem error: %s", exc)
                logger.debug("details", exc_info=True)
                try:
                    if line.is_open:
                        line.hang_up()
                except Exception:
                    pass
                line.close()
            if not stopper.stop:
                logger.info("Back to listening in %.0fs", reconnect_delay)
                time.sleep(reconnect_delay)
    finally:
        if line.is_open:
            try:
                if line.sending_tone:
                    line.stop_dial_tone()
                else:
                    line.hang_up()
            except Exception:
                pass
            line.close()
        if proxy:
            proxy.shutdown()
    return 0


def serve_test_listener(bridge, spec, stopper, proxy):
    host, _, port = spec.rpartition(":")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name != "nt":
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host or "127.0.0.1", int(port)))
    listener.listen(1)
    listener.settimeout(0.5)
    logger.info("TEST MODE: no modem. PPP on tcp %s:%s, one connection at a time",
                host or "127.0.0.1", port)
    try:
        while not stopper.stop:
            try:
                conn, peer = listener.accept()
            except socket.timeout:
                continue
            logger.info("Test link connected from %s:%d", *peer)
            try:
                bridge.run_session(SocketLink(conn), stopper)
            except Exception:
                logger.exception("Test session failed")
            finally:
                conn.close()
    finally:
        listener.close()
        if proxy:
            proxy.shutdown()
    return 0


def do_dry_run(cfg, args):
    bridge = Bridge(cfg)
    device = detect_device(cfg) if not args.test_listen else "(test listener)"
    print("modem          %s @ %s, flow control %s" % (
        device or "NOT FOUND", cfg.get("modem", "speed"),
        cfg.get("modem", "flow_control")))
    print("voice format   AT+VSM=%s" % cfg.get("modem", "voice_sample_mode"))
    print("addresses      this end %s, console %s, DNS %s" % (
        bridge.local_ip, bridge.peer_ip, ", ".join(bridge.dns_ips)))
    print("CHAP           name %s, client %s, key of %d characters" % (
        cfg.get("ppp", "chap_name"), cfg.get("ppp", "chap_client"),
        len(bridge.secret)))
    print("Randnet names  -> %s" % (bridge.server_ip or "not redirected"))
    print("this PC        %s" % ", ".join(sorted(bridge.own)))
    print("proxy          %s" % ("127.0.0.1:%s" % cfg.get("proxy", "port")
                                 if cfg.getboolean("proxy", "enabled") else "off"))
    print("\nrouting")
    for line in bridge.router.describe():
        print("  " + line)
    return 0


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="randnet_win.py",
        description="Answer a Randnet dial-up call on Windows and route the "
                    "console, with no pppd and no admin rights.")
    parser.add_argument("--config", "-c", help="path to an ini config file")
    parser.add_argument("--list-ports", action="store_true",
                        help="list the serial ports Windows knows, then exit")
    parser.add_argument("--probe", action="store_true",
                        help="ask the modem what it supports (voice mode in "
                             "particular), then exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the addresses and routing that would be "
                             "used, then exit")
    parser.add_argument("--self-test", action="store_true",
                        help="run the offline checks, then exit")
    parser.add_argument("--disable-dial-tone", action="store_true",
                        help="send silence instead of a dial tone")
    parser.add_argument("--test-listen", metavar="HOST:PORT",
                        help="development aid: skip the modem and run PPP over "
                             "a TCP connection accepted here (for testing with "
                             "pppd)")
    parser.add_argument("--log-file", help="also write the log to this file")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="log at DEBUG level")
    parser.add_argument("--version", action="version",
                        version="randnet_win " + VERSION)
    return parser


def setup_logging(args):
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if args.verbose else logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s")
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root.addHandler(handler)
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    if args.self_test:
        import win_selftest
        return win_selftest.run()
    setup_logging(args)
    cfg = load_config(args.config)
    if args.list_ports:
        return list_ports(cfg)
    if args.dry_run:
        return do_dry_run(cfg, args)
    if args.probe:
        return probe_modem(cfg, args)

    logger.info("randnet_win %s starting", VERSION)
    stopper = Stopper()
    try:
        return serve(cfg, args, stopper)
    except KeyboardInterrupt:
        return 0
    finally:
        logger.info("randnet_win stopped")


if __name__ == "__main__":
    sys.exit(main())
