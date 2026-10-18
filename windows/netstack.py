"""netstack.py - a userspace NAT for the console's side of the PPP link.

On Linux the kernel routes the console's packets and iptables rewrites some of
them. Windows offers neither without drivers and admin rights, so this module
does the job in user space, the way slirp does for emulators: it terminates
the console's TCP connections and UDP flows here and re-creates them as
ordinary sockets on the PC. No driver, no admin rights, no Windows NAT.

Every redirect randnetpi3.py installs with iptables becomes a routing decision
in route_tcp():

  dns_redirect hosts, port 53      -> the built-in DNS responder
  proxy_hosts ADDR:PORT            -> the browsing proxy on this PC
  Randnet server port 80 (TLS on)  -> a TLS connection to the server's port 443
  any other port 80 (transparent)  -> the browsing proxy on this PC
  everything else                  -> straight out through a normal socket

The console's stack is small and the link is a modem, so the TCP here is
deliberately simple: in-order delivery only (out-of-order segments are dropped
and re-ACKed), go-back-N retransmission from a slow-start window, and no
window scaling, SACK or timestamps.
"""

import collections
import concurrent.futures
import errno
import logging
import queue
import random
import select
import socket
import ssl
import struct
import time

logger = logging.getLogger("randnet-win.net")

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10

RCV_WINDOW = 16384
MAX_INFLIGHT = 4096
UPSTREAM_READ_AHEAD = 16384
RTO_BASE = 3.0
RTO_MAX = 30.0
MAX_RETRIES = 8
CONNECT_TIMEOUT = 15.0
IDLE_TIMEOUT = 900.0
HALF_CLOSED_TIMEOUT = 120.0
TIME_WAIT = 10.0
UDP_IDLE = 60.0
MAX_TCP = 64
MAX_UDP = 64

Target = collections.namedtuple("Target", "kind host port label")



def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip_aton(text):
    return socket.inet_aton(text)


def ip_ntoa(data):
    return socket.inet_ntoa(data)


def seq_add(a, b):
    return (a + b) & 0xFFFFFFFF


def seq_diff(a, b):
    """a - b in sequence space, as a signed number."""
    value = (a - b) & 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def parse_ipv4(packet):
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    total = struct.unpack("!H", packet[2:4])[0]
    if ihl < 20 or total < ihl or total > len(packet):
        return None
    flags_frag = struct.unpack("!H", packet[6:8])[0]
    return {
        "proto": packet[9],
        "src": ip_ntoa(packet[12:16]),
        "dst": ip_ntoa(packet[16:20]),
        "fragment": bool(flags_frag & 0x2000) or bool(flags_frag & 0x1FFF),
        "payload": bytes(packet[ihl:total]),
        "ttl": packet[8],
    }


_ip_ident = [random.randint(0, 0xFFFF)]


def build_ipv4(src, dst, proto, payload, ttl=64):
    _ip_ident[0] = (_ip_ident[0] + 1) & 0xFFFF
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload),
                         _ip_ident[0], 0, ttl, proto, 0,
                         ip_aton(src), ip_aton(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def pseudo_header(src, dst, proto, length):
    return ip_aton(src) + ip_aton(dst) + struct.pack("!BBH", 0, proto, length)


def parse_tcp(segment):
    if len(segment) < 20:
        return None
    sport, dport, seq, ack, offset_flags, window, _, _ = struct.unpack(
        "!HHIIHHHH", segment[:20])
    offset = (offset_flags >> 12) * 4
    if offset < 20 or offset > len(segment):
        return None
    mss = None
    options = segment[20:offset]
    index = 0
    while index < len(options):
        kind = options[index]
        if kind == 0:
            break
        if kind == 1:
            index += 1
            continue
        if index + 1 >= len(options):
            break
        length = options[index + 1]
        if length < 2:
            break
        if kind == 2 and length == 4 and index + 4 <= len(options):
            mss = struct.unpack("!H", options[index + 2:index + 4])[0]
        index += length
    return {
        "sport": sport, "dport": dport, "seq": seq, "ack": ack,
        "flags": offset_flags & 0x3F, "window": window, "mss": mss,
        "data": bytes(segment[offset:]),
    }


def build_tcp(src, dst, sport, dport, seq, ack, flags, window, data=b"",
              mss=None):
    options = struct.pack("!BBH", 2, 4, mss) if mss else b""
    offset = (20 + len(options)) // 4
    header = struct.pack("!HHIIHHHH", sport, dport, seq & 0xFFFFFFFF,
                         ack & 0xFFFFFFFF, (offset << 12) | flags,
                         max(0, min(0xFFFF, window)), 0, 0) + options
    segment = header + data
    csum = checksum(pseudo_header(src, dst, IPPROTO_TCP, len(segment)) + segment)
    segment = segment[:16] + struct.pack("!H", csum) + segment[18:]
    return build_ipv4(src, dst, IPPROTO_TCP, segment)


def parse_udp(datagram):
    if len(datagram) < 8:
        return None
    sport, dport, length, _ = struct.unpack("!HHHH", datagram[:8])
    if length < 8 or length > len(datagram):
        return None
    return {"sport": sport, "dport": dport, "data": bytes(datagram[8:length])}


def build_udp(src, dst, sport, dport, data):
    header = struct.pack("!HHHH", sport, dport, 8 + len(data), 0)
    datagram = header + data
    csum = checksum(pseudo_header(src, dst, IPPROTO_UDP, len(datagram)) + datagram)
    if csum == 0:
        csum = 0xFFFF
    datagram = datagram[:6] + struct.pack("!H", csum) + datagram[8:]
    return build_ipv4(src, dst, IPPROTO_UDP, datagram)



def open_upstream(target, tls_context=None, timeout=CONNECT_TIMEOUT):
    """Runs in a worker thread: connect, and for TLS also handshake."""
    sock = socket.create_connection((target.host, target.port), timeout=timeout)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if target.kind == "tls":
            context = tls_context or ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=target.host)
        sock.setblocking(False)
        return sock
    except BaseException:
        sock.close()
        raise


_WOULD_BLOCK = (BlockingIOError, InterruptedError, ssl.SSLWantReadError,
                ssl.SSLWantWriteError)


class TcpConn(object):

    def __init__(self, stack, key, seg, target):
        self.stack = stack
        self.key = key
        self.src, self.sport, self.dst, self.dport = key
        self.target = target
        self.state = "CONNECTING"
        self.irs = seg["seq"]
        self.rcv_nxt = seq_add(seg["seq"], 1)
        self.iss = random.randint(0, 0xFFFFFFFF)
        self.snd_una = self.iss
        self.snd_nxt = self.iss
        self.snd_max = self.iss
        self.peer_wnd = seg["window"]
        link_mss = max(64, stack.mtu - 40)
        self.mss = max(64, min(seg["mss"] or 536, link_mss))
        self.our_mss = link_mss
        self.cwnd = self.mss * 2
        self.out = bytearray()
        self.to_upstream = bytearray()
        self.upstream_eof = False
        self.fin_sent = False
        self.fin_acked = False
        self.peer_fin = False
        self.shut_wr = False
        self.sock = None
        self.rto = RTO_BASE
        self.rto_deadline = None
        self.retries = 0
        self.last_activity = stack.clock()
        self.closed_at = None
        self.generation = stack.next_generation()
        self.bytes_in = 0
        self.bytes_out = 0
        self.last_window_sent = RCV_WINDOW

    def label(self):
        return "%s:%d -> %s:%d" % (self.src, self.sport, self.dst, self.dport)

    def window(self):
        return max(0, RCV_WINDOW - len(self.to_upstream))

    def emit(self, flags, seq, data=b"", mss=None):
        self.last_window_sent = self.window()
        self.stack.send_packet(build_tcp(
            self.dst, self.src, self.dport, self.sport, seq, self.rcv_nxt,
            flags, self.last_window_sent, data, mss))

    def send_ack(self):
        self.emit(TCP_ACK, self.snd_nxt)

    def send_syn_ack(self):
        self.emit(TCP_SYN | TCP_ACK, self.iss, mss=self.our_mss)
        self.snd_nxt = seq_add(self.iss, 1)
        self.snd_max = self.snd_nxt
        self.arm()

    def _advance_nxt(self, count):
        self.snd_nxt = seq_add(self.snd_nxt, count)
        if seq_diff(self.snd_nxt, self.snd_max) > 0:
            self.snd_max = self.snd_nxt

    def arm(self):
        self.rto_deadline = self.stack.clock() + self.rto

    def disarm(self):
        self.rto_deadline = None

    def unsent(self):
        return len(self.out) - seq_diff(self.snd_nxt, self.snd_una)

    def pump(self, probe=False):
        """Send what the windows allow. Returns True when anything went out."""
        if self.state not in ("ESTABLISHED", "CLOSING"):
            return False
        sent = False
        while True:
            offset = seq_diff(self.snd_nxt, self.snd_una)
            if offset < len(self.out):
                limit = min(self.peer_wnd, self.cwnd, MAX_INFLIGHT)
                room = limit - offset
                if room <= 0:
                    if probe and offset == 0:
                        room = 1
                    else:
                        if offset == 0 and self.rto_deadline is None:
                            self.arm()
                        break
                count = min(self.mss, len(self.out) - offset, room)
                chunk = bytes(self.out[offset:offset + count])
                flags = TCP_ACK
                if offset + count == len(self.out):
                    flags |= TCP_PSH
                self.emit(flags, self.snd_nxt, chunk)
                self._advance_nxt(count)
                if self.rto_deadline is None:
                    self.arm()
                sent = True
                probe = False
            elif (self.upstream_eof and not self.fin_acked
                  and offset == len(self.out)):
                self.emit(TCP_FIN | TCP_ACK, self.snd_nxt)
                self._advance_nxt(1)
                self.fin_sent = True
                if self.rto_deadline is None:
                    self.arm()
                sent = True
                break
            else:
                break
        return sent

    def on_timeout(self):
        nothing_owed = (self.state != "SYN_RCVD"
                        and self.snd_una == self.snd_max
                        and self.unsent() <= 0
                        and not (self.upstream_eof and not self.fin_acked))
        if nothing_owed:
            self.disarm()
            return
        if self.peer_wnd > 0 or self.snd_una != self.snd_max:
            self.retries += 1
        if self.retries > MAX_RETRIES:
            logger.info("TCP %s: no ACK after %d retransmissions, resetting",
                        self.label(), MAX_RETRIES)
            self.stack.reset_conn(self, "retransmission limit")
            return
        self.rto = min(RTO_MAX, self.rto * 2)
        self.cwnd = self.mss
        if self.state == "SYN_RCVD":
            self.send_syn_ack()
            return
        self.snd_nxt = self.snd_una
        self.rto_deadline = None
        if not self.pump(probe=True):
            self.arm()

    def on_segment(self, seg):
        self.last_activity = self.stack.clock()
        flags = seg["flags"]

        if flags & TCP_RST:
            in_flight = min(len(self.out),
                            max(0, seq_diff(self.snd_nxt, self.snd_una)))
            logger.info("TCP %s: reset by the console (%d bytes up, %d down "
                        "acknowledged, %d sent but unacknowledged, upstream "
                        "%s)", self.label(), self.bytes_in, self.bytes_out,
                        in_flight, "closed" if self.upstream_eof else "open")
            self.stack.drop_conn(self)
            return

        if flags & TCP_SYN:
            if seg["seq"] == self.irs:
                if self.state == "SYN_RCVD":
                    self.emit(TCP_SYN | TCP_ACK, self.iss, mss=self.our_mss)
                elif self.state != "CONNECTING":
                    self.send_ack()
                return
            self.stack.drop_conn(self)
            self.stack.on_new_syn(self.key, seg)
            return

        if self.state == "CONNECTING":
            return

        if self.state == "TIME_WAIT":
            if flags & TCP_FIN:
                self.send_ack()
            return

        if not flags & TCP_ACK:
            return

        ack = seg["ack"]
        if self.state == "SYN_RCVD":
            if ack != seq_add(self.iss, 1):
                self.stack.send_packet(build_tcp(
                    self.dst, self.src, self.dport, self.sport, ack, 0,
                    TCP_RST, 0))
                return
            self.state = "ESTABLISHED"
            self.snd_una = ack
            self.retries = 0
            self.rto = RTO_BASE
            self.disarm()
            logger.debug("TCP %s: established", self.label())

        self.peer_wnd = seg["window"]
        advance = seq_diff(ack, self.snd_una)
        if 0 < advance <= seq_diff(self.snd_max, self.snd_una):
            data_acked = min(advance, len(self.out))
            del self.out[:data_acked]
            self.bytes_out += data_acked
            if advance > data_acked and self.fin_sent:
                self.fin_acked = True
            self.snd_una = ack
            if seq_diff(self.snd_nxt, ack) < 0:
                self.snd_nxt = ack
            self.retries = 0
            self.rto = RTO_BASE
            self.cwnd = min(MAX_INFLIGHT, self.cwnd + self.mss)
            if self.snd_una == self.snd_nxt:
                self.disarm()
            else:
                self.arm()

        data = seg["data"]
        fin = bool(flags & TCP_FIN)
        need_ack = False
        if data or fin:
            need_ack = True
            offset = seq_diff(self.rcv_nxt, seg["seq"])
            if offset < 0 or offset > len(data) or (offset == len(data) and not fin):
                data, fin = b"", False
            elif self.peer_fin:
                data, fin = b"", False
            else:
                data = data[offset:]
                room = self.window()
                if len(data) > room:
                    data, fin = data[:room], False
                if data:
                    self.to_upstream += data
                    self.bytes_in += len(data)
                    self.rcv_nxt = seq_add(self.rcv_nxt, len(data))
                if fin:
                    self.rcv_nxt = seq_add(self.rcv_nxt, 1)
                    self.peer_fin = True
                    logger.debug("TCP %s: console closed its side", self.label())

        self.stack.flush_upstream(self)
        if self.stack.tcp.get(self.key) is not self:
            return
        if self.state == "TIME_WAIT":
            if need_ack:
                self.send_ack()
            return
        if not self.pump() and need_ack:
            self.send_ack()
        self.check_closed()

    def check_closed(self):
        if self.state == "TIME_WAIT":
            return
        if self.peer_fin and self.fin_acked and not self.to_upstream:
            self.state = "TIME_WAIT"
            self.closed_at = self.stack.clock()
            self.disarm()
            self.stack.close_upstream(self)
            logger.info("TCP %s: closed (%d bytes up, %d down)",
                        self.label(), self.bytes_in, self.bytes_out)


class UdpFlow(object):
    def __init__(self, key, sock, clock):
        self.key = key
        self.sock = sock
        self.last_activity = clock()


class NatStack(object):
    """send_packet(bytes) hands an IPv4 packet to PPP for the console."""

    def __init__(self, local_ip, peer_ip, send_packet, route_tcp,
                 dns_responder=None, dns_hosts=(), mtu=1500,
                 tls_context=None, clock=time.monotonic, workers=None):
        self.local_ip = local_ip
        self.peer_ip = peer_ip
        self.send_packet = send_packet
        self.route_tcp = route_tcp
        self.dns = dns_responder
        self.dns_hosts = set(dns_hosts or ()) | {local_ip}
        self.mtu = mtu
        self.tls_context = tls_context
        self.clock = clock
        self.tcp = {}
        self.udp = {}
        self.results = queue.Queue()
        self._own_pool = workers is None
        self.pool = workers or concurrent.futures.ThreadPoolExecutor(
            max_workers=8)
        self._generation = 0
        self.stats = collections.Counter()

    def next_generation(self):
        self._generation += 1
        return self._generation

    def submit(self, func, *args, **kwargs):
        future = self.pool.submit(func, *args, **kwargs)
        return future


    def handle_packet(self, packet):
        ip = parse_ipv4(packet)
        if ip is None:
            self.stats["bad_ip"] += 1
            return
        if ip["fragment"]:
            self.stats["fragments"] += 1
            logger.debug("IP fragment from %s dropped", ip["src"])
            return
        if ip["proto"] == IPPROTO_TCP:
            self._handle_tcp(ip)
        elif ip["proto"] == IPPROTO_UDP:
            self._handle_udp(ip)
        elif ip["proto"] == IPPROTO_ICMP:
            self._handle_icmp(ip)
        else:
            self.stats["other_proto"] += 1


    def _handle_icmp(self, ip):
        data = ip["payload"]
        if len(data) < 8 or data[0] != 8:
            return
        if ip["dst"] != self.local_ip:
            self.stats["icmp_dropped"] += 1
            logger.debug("ping to %s not answered (only %s answers pings)",
                         ip["dst"], self.local_ip)
            return
        reply = b"\x00\x00\x00\x00" + data[4:]
        reply = reply[:2] + struct.pack("!H", checksum(reply)) + reply[4:]
        self.send_packet(build_ipv4(ip["dst"], ip["src"], IPPROTO_ICMP, reply))


    def _handle_udp(self, ip):
        udp = parse_udp(ip["payload"])
        if udp is None:
            return
        if udp["dport"] == 53 and ip["dst"] in self.dns_hosts and self.dns:
            src, sport, dst = ip["src"], udp["sport"], ip["dst"]

            def reply(payload, src=src, sport=sport, dst=dst):
                self.send_packet(build_udp(dst, src, 53, sport, payload))

            self.dns.handle(udp["data"], reply)
            return

        key = (ip["src"], udp["sport"], ip["dst"], udp["dport"])
        flow = self.udp.get(key)
        if flow is None:
            if len(self.udp) >= MAX_UDP:
                oldest = min(self.udp.values(), key=lambda f: f.last_activity)
                self._close_udp(oldest)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                sock.connect((ip["dst"], udp["dport"]))
            except OSError as exc:
                logger.debug("UDP to %s:%d failed: %s", ip["dst"], udp["dport"], exc)
                return
            flow = UdpFlow(key, sock, self.clock)
            self.udp[key] = flow
        flow.last_activity = self.clock()
        try:
            flow.sock.send(udp["data"])
        except OSError as exc:
            logger.debug("UDP send to %s:%d failed: %s", ip["dst"], udp["dport"], exc)

    def _close_udp(self, flow):
        self.udp.pop(flow.key, None)
        try:
            flow.sock.close()
        except OSError:
            pass


    def _handle_tcp(self, ip):
        seg = parse_tcp(ip["payload"])
        if seg is None:
            return
        key = (ip["src"], seg["sport"], ip["dst"], seg["dport"])
        conn = self.tcp.get(key)
        if conn is not None:
            conn.on_segment(seg)
            return
        flags = seg["flags"]
        if flags & TCP_RST:
            return
        if flags & TCP_SYN and not flags & TCP_ACK:
            self.on_new_syn(key, seg)
            return
        self._send_rst_for(key, seg)

    def _send_rst_for(self, key, seg):
        src, sport, dst, dport = key
        if seg["flags"] & TCP_ACK:
            packet = build_tcp(dst, src, dport, sport, seg["ack"], 0, TCP_RST, 0)
        else:
            length = len(seg["data"]) + (1 if seg["flags"] & TCP_SYN else 0) \
                + (1 if seg["flags"] & TCP_FIN else 0)
            packet = build_tcp(dst, src, dport, sport, 0,
                               seq_add(seg["seq"], length), TCP_RST | TCP_ACK, 0)
        self.send_packet(packet)

    def on_new_syn(self, key, seg):
        src, sport, dst, dport = key
        target = self.route_tcp(dst, dport)
        if target is None or target.kind == "refuse":
            logger.info("TCP %s:%d -> %s:%d refused%s", src, sport, dst, dport,
                        " (%s)" % target.label if target else "")
            self._send_rst_for(key, seg)
            return
        if len(self.tcp) >= MAX_TCP:
            logger.warning("TCP: %d connections open, refusing another", MAX_TCP)
            self._send_rst_for(key, seg)
            return
        conn = TcpConn(self, key, seg, target)
        self.tcp[key] = conn
        logger.info("TCP %s via %s", conn.label(), target.label)
        future = self.submit(open_upstream, target, self.tls_context)
        generation = conn.generation
        future.add_done_callback(
            lambda f, k=key, g=generation: self.results.put(("connect", k, g, f)))

    def reset_conn(self, conn, reason):
        if conn.state != "TIME_WAIT":
            self.send_packet(build_tcp(conn.dst, conn.src, conn.dport, conn.sport,
                                       conn.snd_nxt, conn.rcv_nxt,
                                       TCP_RST | TCP_ACK, 0))
        logger.debug("TCP %s: reset (%s)", conn.label(), reason)
        self.drop_conn(conn)

    def drop_conn(self, conn):
        self.close_upstream(conn)
        if self.tcp.get(conn.key) is conn:
            del self.tcp[conn.key]

    def close_upstream(self, conn):
        if conn.sock is not None:
            try:
                conn.sock.close()
            except OSError:
                pass
            conn.sock = None

    def flush_upstream(self, conn):
        if conn.sock is None or conn.state == "CONNECTING":
            return
        window_before = conn.window()
        while conn.to_upstream:
            try:
                sent = conn.sock.send(conn.to_upstream[:16384])
            except _WOULD_BLOCK:
                break
            except OSError as exc:
                logger.info("TCP %s: upstream write failed: %s", conn.label(), exc)
                self.reset_conn(conn, "upstream write")
                return
            if not sent:
                break
            del conn.to_upstream[:sent]
        if conn.peer_fin and not conn.to_upstream and not conn.shut_wr:
            conn.shut_wr = True
            try:
                conn.sock.shutdown(socket.SHUT_WR)
            except (OSError, ValueError):
                pass
        if (conn.last_window_sent < conn.mss <= conn.window()
                and window_before < conn.window()):
            conn.send_ack()
        conn.check_closed()

    def read_upstream(self, conn):
        if conn.sock is None:
            return
        while not conn.upstream_eof and conn.unsent() < UPSTREAM_READ_AHEAD:
            try:
                data = conn.sock.recv(8192)
            except _WOULD_BLOCK:
                break
            except (OSError, ssl.SSLError) as exc:
                logger.info("TCP %s: upstream read failed: %s", conn.label(), exc)
                self.reset_conn(conn, "upstream read")
                return
            if not data:
                conn.upstream_eof = True
                logger.debug("TCP %s: upstream closed", conn.label())
                break
            conn.out += data
            if not isinstance(conn.sock, ssl.SSLSocket) or not conn.sock.pending():
                break
        conn.pump()


    def _on_connect_result(self, key, generation, future):
        conn = self.tcp.get(key)
        try:
            sock = future.result()
        except Exception as exc:
            if conn is not None and conn.generation == generation:
                logger.info("TCP %s: upstream %s:%d failed: %s", conn.label(),
                            conn.target.host, conn.target.port, exc)
                self.send_packet(build_tcp(conn.dst, conn.src, conn.dport,
                                           conn.sport, 0, conn.rcv_nxt,
                                           TCP_RST | TCP_ACK, 0))
                del self.tcp[key]
            return
        if conn is None or conn.generation != generation:
            sock.close()
            return
        conn.sock = sock
        conn.state = "SYN_RCVD"
        conn.send_syn_ack()

    def poll(self, timeout=0.01):
        """Service sockets, worker results and timers once."""
        while True:
            try:
                item = self.results.get_nowait()
            except queue.Empty:
                break
            kind = item[0]
            if kind == "connect":
                self._on_connect_result(*item[1:])
            elif kind == "call":
                item[1]()

        readers, writers, extra = [], [], []
        by_sock = {}
        for conn in list(self.tcp.values()):
            sock = conn.sock
            if sock is None or conn.state in ("CONNECTING", "SYN_RCVD"):
                continue
            by_sock[sock.fileno()] = ("tcp", conn)
            if not conn.upstream_eof and conn.unsent() < UPSTREAM_READ_AHEAD:
                readers.append(sock)
                if isinstance(sock, ssl.SSLSocket) and sock.pending():
                    extra.append(sock)
            if conn.to_upstream:
                writers.append(sock)
        for flow in list(self.udp.values()):
            by_sock[flow.sock.fileno()] = ("udp", flow)
            readers.append(flow.sock)

        wait = 0 if extra else timeout
        if readers or writers:
            try:
                readable, writable, _ = select.select(readers, writers, [], wait)
            except (OSError, ValueError):
                readable, writable = readers, writers
        else:
            if wait:
                time.sleep(wait)
            readable, writable = [], []
        readable = list(readable) + [s for s in extra if s not in readable]

        for sock in writable:
            entry = by_sock.get(sock.fileno()) if sock.fileno() >= 0 else None
            if entry and entry[0] == "tcp":
                self.flush_upstream(entry[1])
        for sock in readable:
            try:
                fileno = sock.fileno()
            except OSError:
                continue
            entry = by_sock.get(fileno) if fileno >= 0 else None
            if not entry:
                continue
            if entry[0] == "tcp":
                if entry[1].sock is sock:
                    self.read_upstream(entry[1])
            else:
                self._read_udp(entry[1])

        self._run_timers()

    def _read_udp(self, flow):
        src, sport, dst, dport = flow.key
        for _ in range(16):
            try:
                data = flow.sock.recv(65535)
            except _WOULD_BLOCK:
                return
            except OSError:
                return
            flow.last_activity = self.clock()
            self.send_packet(build_udp(dst, src, dport, sport, data))

    def _run_timers(self):
        now = self.clock()
        for conn in list(self.tcp.values()):
            if conn.state == "TIME_WAIT":
                if now - conn.closed_at >= TIME_WAIT:
                    self.drop_conn(conn)
                continue
            if conn.rto_deadline is not None and now >= conn.rto_deadline:
                conn.on_timeout()
                if self.tcp.get(conn.key) is not conn:
                    continue
            idle = now - conn.last_activity
            limit = HALF_CLOSED_TIMEOUT if (conn.peer_fin or conn.upstream_eof) \
                else IDLE_TIMEOUT
            if conn.state == "CONNECTING":
                limit = CONNECT_TIMEOUT * 2
            if idle > limit:
                logger.info("TCP %s: idle for %ds, resetting", conn.label(), idle)
                self.reset_conn(conn, "idle")
        for flow in list(self.udp.values()):
            if now - flow.last_activity > UDP_IDLE:
                self._close_udp(flow)

    def close_all(self):
        for conn in list(self.tcp.values()):
            self.drop_conn(conn)
        for flow in list(self.udp.values()):
            self._close_udp(flow)
        if self._own_pool:
            self.pool.shutdown(wait=False)
