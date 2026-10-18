"""ppp.py - a userspace PPP server for one async serial link.

This replaces pppd on Windows. It plays the same role pppd plays in
randnetpi3.py: the authenticator end of the link, with the options the Linux
peers file asks for (nopcomp, noaccomp, require-chap, noccp, ms-dns).

  RFC 1662  async HDLC-like framing and FCS-16
  RFC 1661  LCP
  RFC 1994  CHAP with MD5 (we are the authenticator)
  RFC 1332  IPCP, plus RFC 1877 for the DNS server option

No third party dependencies and nothing platform specific: the caller supplies
a function that writes bytes to the line and feeds back what it reads.
"""

import binascii
import hashlib
import logging
import os
import struct
import time

logger = logging.getLogger("randnet-win.ppp")

PROTO_IP = 0x0021
PROTO_IPCP = 0x8021
PROTO_LCP = 0xC021
PROTO_PAP = 0xC023
PROTO_CHAP = 0xC223

PROTO_NAMES = {
    PROTO_IP: "IP", PROTO_IPCP: "IPCP", PROTO_LCP: "LCP",
    PROTO_PAP: "PAP", PROTO_CHAP: "CHAP", 0x80FD: "CCP", 0x8057: "IPv6CP",
    0x0057: "IPv6", 0x002D: "VJ-comp", 0x002F: "VJ-uncomp",
}

CONF_REQ, CONF_ACK, CONF_NAK, CONF_REJ = 1, 2, 3, 4
TERM_REQ, TERM_ACK, CODE_REJ, PROTO_REJ = 5, 6, 7, 8
ECHO_REQ, ECHO_REP, DISCARD_REQ = 9, 10, 11

CHAP_CHALLENGE, CHAP_RESPONSE, CHAP_SUCCESS, CHAP_FAILURE = 1, 2, 3, 4
CHAP_MD5 = 5

LCP_MRU, LCP_ACCM, LCP_AUTH, LCP_MAGIC, LCP_PFC, LCP_ACFC = 1, 2, 3, 5, 7, 8
IPCP_ADDRESSES, IPCP_COMPRESSION, IPCP_ADDRESS = 1, 2, 3
IPCP_DNS1, IPCP_NBNS1, IPCP_DNS2, IPCP_NBNS2 = 129, 130, 131, 132

FLAG = 0x7E
ESCAPE = 0x7D

DEFAULT_MRU = 1500
MAX_FRAME = 4096

RESTART_INTERVAL = 3.0
MAX_CONFIGURE = 10



def _make_fcs_table():
    table = []
    for byte in range(256):
        value = byte
        for _ in range(8):
            value = (value >> 1) ^ 0x8408 if value & 1 else value >> 1
        table.append(value)
    return table


FCS_TABLE = _make_fcs_table()
FCS_INIT = 0xFFFF
FCS_GOOD = 0xF0B8


def fcs16(data, fcs=FCS_INIT):
    for byte in data:
        fcs = (fcs >> 8) ^ FCS_TABLE[(fcs ^ byte) & 0xFF]
    return fcs


def hdlc_encode(protocol, info):
    """Frame one PPP packet for the wire.

    Every byte below 0x20 is escaped whatever the peer's ACCM says. Escaping
    more than the negotiated map requires is always safe, because the receiver
    unescapes any 7D pair; escaping less is what breaks links.
    """
    body = b"\xff\x03" + struct.pack(">H", protocol) + bytes(info)
    fcs = fcs16(body) ^ 0xFFFF
    body += struct.pack("<H", fcs)

    out = bytearray([FLAG])
    for byte in body:
        if byte < 0x20 or byte in (FLAG, ESCAPE):
            out.append(ESCAPE)
            out.append(byte ^ 0x20)
        else:
            out.append(byte)
    out.append(FLAG)
    return bytes(out)


class HdlcDecoder(object):
    """Turns the raw byte stream back into frames with a good FCS."""

    def __init__(self):
        self._buf = bytearray()
        self._escaped = False
        self.rx_accm = 0xFFFFFFFF
        self.good = 0
        self.bad_fcs = 0
        self.runts = 0
        self.overruns = 0

    def feed(self, data):
        frames = []
        for byte in data:
            if byte == FLAG:
                if self._buf and not self._escaped:
                    frame = self._finish()
                    if frame is not None:
                        frames.append(frame)
                self._buf = bytearray()
                self._escaped = False
                continue
            if byte == ESCAPE:
                self._escaped = True
                continue
            if byte < 0x20 and not self._escaped and self.rx_accm & (1 << byte):
                continue
            if self._escaped:
                byte ^= 0x20
                self._escaped = False
            if len(self._buf) >= MAX_FRAME:
                self.overruns += 1
                self._buf = bytearray()
                continue
            self._buf.append(byte)
        return frames

    def _finish(self):
        data = bytes(self._buf)
        if len(data) < 4:
            self.runts += 1
            return None
        if fcs16(data) != FCS_GOOD:
            self.bad_fcs += 1
            return None
        self.good += 1
        return data[:-2]


def split_frame(frame):
    """Return (protocol, info) from an unescaped frame without its FCS."""
    data = frame
    if data[:2] == b"\xff\x03":
        data = data[2:]
    if not data:
        return None, b""
    if data[0] & 1:
        return data[0], data[1:]
    if len(data) < 2:
        return None, b""
    return (data[0] << 8) | data[1], data[2:]



def parse_options(data):
    """Return a list of (type, value) or None when the list is malformed."""
    options = []
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            return None
        kind, length = data[offset], data[offset + 1]
        if length < 2 or offset + length > len(data):
            return None
        options.append((kind, bytes(data[offset + 2: offset + length])))
        offset += length
    return options


def build_options(options):
    out = bytearray()
    for kind, value in options:
        out += bytes([kind, len(value) + 2]) + value
    return bytes(out)


def build_packet(code, ident, data=b""):
    return struct.pack(">BBH", code, ident & 0xFF, len(data) + 4) + data


def parse_packet(info):
    if len(info) < 4:
        return None
    code, ident, length = struct.unpack(">BBH", info[:4])
    if length < 4 or length > len(info):
        return None
    return code, ident, bytes(info[4:length])


def ip_bytes(address):
    return bytes(int(octet) for octet in address.split("."))


def ip_text(data):
    return ".".join(str(byte) for byte in data)


def describe_name(raw):
    """The CHAP name for the log: text if it is printable ASCII, else hex.

    The Randnet disk sends a binary blob there, not a readable user name.
    """
    if raw and all(0x20 <= b < 0x7F for b in raw):
        return repr(raw.decode("ascii"))
    return "<%d bytes: %s>" % (len(raw), binascii.hexlify(raw).decode("ascii"))


def chap_md5(ident, secret, challenge):
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hashlib.md5(bytes([ident & 0xFF]) + secret + challenge).digest()



class ConfigureState(object):
    """The half of a configure exchange that we drive: our own request."""

    def __init__(self, name, clock):
        self.name = name
        self.clock = clock
        self.ident = 0
        self.acked = False
        self.peer_acked = False
        self.sent_at = None
        self.attempts = 0

    def next_ident(self):
        self.ident = (self.ident + 1) & 0xFF
        return self.ident

    def reset(self):
        self.acked = False
        self.peer_acked = False
        self.sent_at = None
        self.attempts = 0

    @property
    def opened(self):
        return self.acked and self.peer_acked

    def due(self):
        return (not self.acked and self.sent_at is not None
                and self.clock() - self.sent_at >= RESTART_INTERVAL)


class PppServer(object):
    """The authenticator end of one PPP session.

    send_raw(bytes)          writes framed bytes to the line
    on_ip(packet)            receives every IPv4 packet once IPCP is up
    on_up(local, peer)       optional, called when IPCP opens
    """

    def __init__(self, send_raw, on_ip, local_ip, peer_ip, dns_ips,
                 chap_name, chap_secret, chap_client="*",
                 echo_interval=30.0, echo_failure=4, on_up=None,
                 clock=time.monotonic, rng=os.urandom):
        self._send_raw = send_raw
        self._on_ip = on_ip
        self._on_up = on_up
        self.local_ip = local_ip
        self.peer_ip = peer_ip
        self.dns_ips = [ip for ip in (dns_ips or []) if ip][:2]
        self.chap_name = chap_name
        self.chap_secret = chap_secret
        self.chap_client = chap_client or "*"
        self.echo_interval = float(echo_interval or 0)
        self.echo_failure = int(echo_failure or 0)
        self.clock = clock
        self.rng = rng

        self.decoder = HdlcDecoder()

        self.phase = "establish"
        self.dead = False
        self.dead_reason = None
        self.peer_name = None
        self.peer_mru = DEFAULT_MRU

        self.lcp = ConfigureState("LCP", clock)
        self.ipcp = ConfigureState("IPCP", clock)
        self.magic = struct.unpack(">I", rng(4))[0] or 0x52414E44
        self.peer_magic = 0
        self._lcp_options = [
            (LCP_ACCM, b"\x00\x00\x00\x00"),
            (LCP_AUTH, struct.pack(">HB", PROTO_CHAP, CHAP_MD5)),
            (LCP_MAGIC, struct.pack(">I", self.magic)),
        ]
        self._ipcp_options = [(IPCP_ADDRESS, ip_bytes(local_ip))]
        self._ipcp_naks_without_address = 0

        self._chap_ident = 0
        self._chap_challenge = b""
        self._chap_sent_at = None
        self._chap_attempts = 0
        self._chap_done = False

        self._echo_ident = 0
        self._echo_next = None
        self._echo_outstanding = 0

        self._term_sent_at = None
        self._term_attempts = 0
        self._ip_up = False

        self.stats = {"rx_ip": 0, "tx_ip": 0, "proto_rej": 0}


    @property
    def ip_up(self):
        return self._ip_up

    def start(self):
        logger.info("PPP: starting LCP negotiation")
        self._send_lcp_request()

    def feed(self, data):
        for frame in self.decoder.feed(data):
            try:
                self._handle_frame(frame)
            except Exception:
                logger.exception("PPP: error handling a frame; dropped")

    def poll(self):
        """Run the retransmit and keepalive timers. Call often."""
        if self.dead:
            return
        now = self.clock()

        if self._term_sent_at is not None:
            if now - self._term_sent_at >= RESTART_INTERVAL:
                if self._term_attempts >= 2:
                    self._die(self.dead_reason or "terminated")
                else:
                    self._send_term_request(self.dead_reason)
            return

        if self.lcp.due():
            if self.lcp.attempts >= MAX_CONFIGURE:
                self._die("LCP: no answer to %d Configure-Requests"
                          % self.lcp.attempts)
                return
            self._send_lcp_request()

        if (self.phase == "auth" and not self._chap_done
                and self._chap_sent_at is not None
                and now - self._chap_sent_at >= RESTART_INTERVAL):
            if self._chap_attempts >= MAX_CONFIGURE:
                self.terminate("CHAP: no response to the challenge")
                return
            self._send_chap_challenge(new=False)

        if self.phase == "network" and self.ipcp.due():
            if self.ipcp.attempts >= MAX_CONFIGURE:
                self.terminate("IPCP: no answer to %d Configure-Requests"
                               % self.ipcp.attempts)
                return
            self._send_ipcp_request()

        if (self.lcp.opened and self.echo_interval > 0
                and self._echo_next is not None and now >= self._echo_next):
            if self.echo_failure and self._echo_outstanding >= self.echo_failure:
                self._die("LCP: %d echo requests unanswered, link is dead"
                          % self._echo_outstanding)
                return
            self._echo_ident = (self._echo_ident + 1) & 0xFF
            self._send_lcp(ECHO_REQ, self._echo_ident,
                           struct.pack(">I", self.magic))
            self._echo_outstanding += 1
            self._echo_next = now + self.echo_interval

    def send_ip(self, packet):
        if not self._ip_up or self.dead:
            return False
        self.stats["tx_ip"] += 1
        self._send_raw(hdlc_encode(PROTO_IP, packet))
        return True

    def terminate(self, reason):
        if self.dead or self._term_sent_at is not None:
            return
        logger.info("PPP: terminating (%s)", reason)
        self.dead_reason = reason
        self._ip_up = False
        self.phase = "terminate"
        self._send_term_request(reason)


    def _die(self, reason):
        if self.dead:
            return
        self.dead = True
        self.dead_reason = reason
        self._ip_up = False
        self.phase = "dead"
        logger.info("PPP: link down (%s)", reason)

    def _send(self, protocol, info):
        self._send_raw(hdlc_encode(protocol, info))

    def _send_lcp(self, code, ident, data=b""):
        self._send(PROTO_LCP, build_packet(code, ident, data))

    def _send_term_request(self, reason):
        self._term_attempts += 1
        self._term_sent_at = self.clock()
        self._send_lcp(TERM_REQ, self.lcp.next_ident(),
                       (reason or "").encode("ascii", "replace")[:64])

    def _handle_frame(self, frame):
        protocol, info = split_frame(frame)
        if protocol is None:
            return

        if protocol == PROTO_LCP:
            self._handle_lcp(info)
            return

        if self.dead or self._term_sent_at is not None:
            return

        if not self.lcp.opened:
            logger.debug("PPP: %s before LCP is open, dropped",
                         PROTO_NAMES.get(protocol, "0x%04x" % protocol))
            return

        if protocol == PROTO_CHAP:
            self._handle_chap(info)
        elif protocol == PROTO_IPCP:
            if self.phase == "network":
                self._handle_ipcp(info)
            else:
                logger.debug("PPP: IPCP during %s phase, dropped", self.phase)
        elif protocol == PROTO_IP:
            if self._ip_up:
                self.stats["rx_ip"] += 1
                self._on_ip(bytes(info))
        elif protocol == PROTO_PAP:
            logger.warning("PPP: the console sent PAP but CHAP was agreed; "
                           "dropped")
        else:
            self.stats["proto_rej"] += 1
            logger.info("PPP: Protocol-Reject for %s",
                        PROTO_NAMES.get(protocol, "0x%04x" % protocol))
            room = max(0, self.peer_mru - 6)
            self._send_lcp(PROTO_REJ, self.lcp.next_ident(),
                           struct.pack(">H", protocol) + bytes(info[:room]))


    def _send_lcp_request(self):
        self.lcp.attempts += 1
        self.lcp.sent_at = self.clock()
        self._send_lcp(CONF_REQ, self.lcp.next_ident(),
                       build_options(self._lcp_options))

    def _handle_lcp(self, info):
        packet = parse_packet(info)
        if packet is None:
            return
        code, ident, data = packet

        if code == CONF_REQ:
            if self._term_sent_at is not None or self.dead:
                return
            if self.lcp.opened:
                logger.info("PPP: peer renegotiating LCP, restarting the link")
                self._link_restart()
            self._handle_lcp_request(ident, data)
        elif code == CONF_ACK:
            if ident == self.lcp.ident and not self.lcp.acked:
                self.lcp.acked = True
                self._maybe_lcp_up()
        elif code == CONF_NAK:
            if ident == self.lcp.ident:
                self._handle_lcp_nak(data)
        elif code == CONF_REJ:
            if ident == self.lcp.ident:
                self._handle_lcp_reject(data)
        elif code == TERM_REQ:
            self._send_lcp(TERM_ACK, ident)
            message = data.decode("ascii", "replace").strip()
            self._die("peer sent Terminate-Request%s"
                      % (": %s" % message if message else ""))
        elif code == TERM_ACK:
            if self._term_sent_at is not None:
                self._die(self.dead_reason or "terminated")
        elif code == ECHO_REQ:
            if self.lcp.opened:
                self._send_lcp(ECHO_REP, ident, struct.pack(">I", self.magic)
                               + data[4:])
        elif code == ECHO_REP:
            self._echo_outstanding = 0
        elif code == CODE_REJ:
            logger.warning("PPP: peer sent Code-Reject")
        elif code == PROTO_REJ:
            if len(data) >= 2:
                rejected = struct.unpack(">H", data[:2])[0]
                logger.warning("PPP: peer rejected protocol %s",
                               PROTO_NAMES.get(rejected, "0x%04x" % rejected))
                if rejected in (PROTO_IPCP, PROTO_IP):
                    self.terminate("peer rejected IP")
        elif code == DISCARD_REQ:
            pass
        else:
            self._send_lcp(CODE_REJ, self.lcp.next_ident(), info[:self.peer_mru - 4])

    def _handle_lcp_request(self, ident, data):
        options = parse_options(data)
        if options is None:
            logger.warning("PPP: malformed LCP Configure-Request, dropped")
            return

        rejects, naks = [], []
        mru = DEFAULT_MRU
        peer_magic = 0
        for kind, value in options:
            if kind == LCP_MRU and len(value) == 2:
                mru = struct.unpack(">H", value)[0]
                if mru < 128:
                    naks.append((LCP_MRU, struct.pack(">H", DEFAULT_MRU)))
            elif kind == LCP_ACCM and len(value) == 4:
                pass
            elif kind == LCP_MAGIC and len(value) == 4:
                peer_magic = struct.unpack(">I", value)[0]
                if peer_magic == self.magic and peer_magic != 0:
                    naks.append((LCP_MAGIC, self.rng(4)))
            else:
                rejects.append((kind, value))

        if rejects:
            logger.debug("PPP: LCP rejecting options %s",
                         [kind for kind, _ in rejects])
            self._send_lcp(CONF_REJ, ident, build_options(rejects))
            self.lcp.peer_acked = False
            return
        if naks:
            self._send_lcp(CONF_NAK, ident, build_options(naks))
            self.lcp.peer_acked = False
            return

        self.peer_mru = mru
        self.peer_magic = peer_magic
        self._send_lcp(CONF_ACK, ident, data)
        self.lcp.peer_acked = True
        if not self.lcp.acked and self.lcp.sent_at is None:
            self._send_lcp_request()
        self._maybe_lcp_up()

    def _handle_lcp_nak(self, data):
        options = parse_options(data) or []
        for kind, value in options:
            if kind == LCP_ACCM and len(value) == 4:
                self._replace_lcp_option(LCP_ACCM, value)
            elif kind == LCP_MAGIC:
                self.magic = struct.unpack(">I", self.rng(4))[0] or 1
                self._replace_lcp_option(LCP_MAGIC, struct.pack(">I", self.magic))
            elif kind == LCP_AUTH:
                logger.warning(
                    "PPP: the console asked for a different authentication "
                    "protocol (%s); CHAP is required, asking again",
                    binascii.hexlify(value).decode("ascii"))
            elif kind == LCP_MRU:
                pass
        self._send_lcp_request()

    def _handle_lcp_reject(self, data):
        options = parse_options(data) or []
        for kind, _ in options:
            if kind == LCP_AUTH:
                self.terminate("the console refused to authenticate with CHAP")
                return
            self._lcp_options = [(k, v) for k, v in self._lcp_options if k != kind]
        self._send_lcp_request()

    def _replace_lcp_option(self, kind, value):
        self._lcp_options = [(k, value if k == kind else v)
                             for k, v in self._lcp_options]

    def _link_restart(self):
        self.lcp.reset()
        self.ipcp.reset()
        self._ip_up = False
        self._chap_done = False
        self._chap_sent_at = None
        self._chap_attempts = 0
        self.phase = "establish"
        self.decoder.rx_accm = 0xFFFFFFFF
        self._send_lcp_request()

    def _maybe_lcp_up(self):
        if not self.lcp.opened or self.phase != "establish":
            return
        accm = dict(self._lcp_options).get(LCP_ACCM)
        if accm is not None:
            self.decoder.rx_accm = struct.unpack(">I", accm)[0]
        logger.info("PPP: LCP open (peer MRU %d, magic %08x)",
                    self.peer_mru, self.peer_magic)
        if self.echo_interval > 0:
            self._echo_next = self.clock() + self.echo_interval
        self.phase = "auth"
        self._send_chap_challenge(new=True)


    def _send_chap_challenge(self, new):
        if new or not self._chap_challenge:
            self._chap_ident = (self._chap_ident + 1) & 0xFF
            self._chap_challenge = self.rng(16)
        self._chap_attempts += 1
        self._chap_sent_at = self.clock()
        name = self.chap_name.encode("utf-8")
        data = bytes([len(self._chap_challenge)]) + self._chap_challenge + name
        self._send(PROTO_CHAP, build_packet(CHAP_CHALLENGE, self._chap_ident, data))

    def _handle_chap(self, info):
        packet = parse_packet(info)
        if packet is None:
            return
        code, ident, data = packet
        if code != CHAP_RESPONSE:
            return
        if not data:
            return
        size = data[0]
        value = data[1:1 + size]
        raw_name = bytes(data[1 + size:])
        name = raw_name.decode("latin-1")
        shown = describe_name(raw_name)

        if self._chap_done:
            if ident == self._chap_ident:
                self._send(PROTO_CHAP, build_packet(CHAP_SUCCESS, ident, b"Welcome"))
            return
        if ident != self._chap_ident:
            logger.debug("PPP: stale CHAP response id %d, expected %d",
                         ident, self._chap_ident)
            return

        self.peer_name = name
        expected = chap_md5(ident, self.chap_secret, self._chap_challenge)
        name_ok = self.chap_client == "*" or name == self.chap_client
        if value == expected and name_ok:
            self._chap_done = True
            self._send(PROTO_CHAP, build_packet(CHAP_SUCCESS, ident, b"Welcome"))
            logger.info("PPP: CHAP authentication succeeded (console name %s)", shown)
            self.phase = "network"
            self._send_ipcp_request()
            return

        self._send(PROTO_CHAP, build_packet(CHAP_FAILURE, ident,
                                            b"Authentication failed"))
        if not name_ok:
            logger.error("PPP: CHAP name %s is not the configured chap_client "
                         "%r", shown, self.chap_client)
        else:
            logger.error(
                "PPP: CHAP authentication FAILED (console name %s). The key "
                "does not match ppp.chap_secret. Read the key off the disk "
                "with extract_member.py or randnet_diskread.n64.", shown)
        self.terminate("CHAP authentication failed")


    def _send_ipcp_request(self):
        self.ipcp.attempts += 1
        self.ipcp.sent_at = self.clock()
        self._send(PROTO_IPCP, build_packet(CONF_REQ, self.ipcp.next_ident(),
                                            build_options(self._ipcp_options)))

    def _handle_ipcp(self, info):
        packet = parse_packet(info)
        if packet is None:
            return
        code, ident, data = packet

        if code == CONF_REQ:
            if self._ip_up:
                logger.info("PPP: peer renegotiating IPCP")
                self._ip_up = False
                self.ipcp.reset()
                self._send_ipcp_request()
            self._handle_ipcp_request(ident, data)
        elif code == CONF_ACK:
            if ident == self.ipcp.ident:
                self.ipcp.acked = True
                self._maybe_ipcp_up()
        elif code == CONF_NAK:
            if ident == self.ipcp.ident:
                for kind, value in parse_options(data) or []:
                    if kind == IPCP_ADDRESS:
                        logger.info("PPP: console suggested %s for this end; "
                                    "keeping %s", ip_text(value), self.local_ip)
                self._send_ipcp_request()
        elif code == CONF_REJ:
            if ident == self.ipcp.ident:
                rejected = [kind for kind, _ in parse_options(data) or []]
                self._ipcp_options = [(k, v) for k, v in self._ipcp_options
                                      if k not in rejected]
                self._send_ipcp_request()
        elif code == TERM_REQ:
            self._send(PROTO_IPCP, build_packet(TERM_ACK, ident))
            self.terminate("peer closed IPCP")
        elif code == TERM_ACK:
            pass
        else:
            self._send(PROTO_IPCP, build_packet(CODE_REJ, self.ipcp.next_ident(),
                                                info[:self.peer_mru - 4]))

    def _handle_ipcp_request(self, ident, data):
        options = parse_options(data)
        if options is None:
            return

        rejects, naks = [], []
        saw_address = False
        dns_by_option = {IPCP_DNS1: 0, IPCP_DNS2: 1}
        for kind, value in options:
            if kind == IPCP_ADDRESS and len(value) == 4:
                saw_address = True
                if ip_text(value) != self.peer_ip:
                    naks.append((IPCP_ADDRESS, ip_bytes(self.peer_ip)))
            elif kind in dns_by_option and len(value) == 4:
                index = dns_by_option[kind]
                if index >= len(self.dns_ips):
                    rejects.append((kind, value))
                elif ip_text(value) != self.dns_ips[index]:
                    naks.append((kind, ip_bytes(self.dns_ips[index])))
            else:
                rejects.append((kind, value))

        if rejects:
            logger.debug("PPP: IPCP rejecting options %s",
                         [kind for kind, _ in rejects])
            self._send(PROTO_IPCP, build_packet(CONF_REJ, ident,
                                                build_options(rejects)))
            self.ipcp.peer_acked = False
            return

        if not saw_address and self._ipcp_naks_without_address < 3:
            self._ipcp_naks_without_address += 1
            naks.append((IPCP_ADDRESS, ip_bytes(self.peer_ip)))

        if naks:
            self._send(PROTO_IPCP, build_packet(CONF_NAK, ident,
                                                build_options(naks)))
            self.ipcp.peer_acked = False
            return

        self._send(PROTO_IPCP, build_packet(CONF_ACK, ident, data))
        self.ipcp.peer_acked = True
        self._maybe_ipcp_up()

    def _maybe_ipcp_up(self):
        if not self.ipcp.opened or self._ip_up:
            return
        self._ip_up = True
        logger.info("PPP: IPCP open - this end %s, console %s, DNS %s",
                    self.local_ip, self.peer_ip,
                    ", ".join(self.dns_ips) or "none")
        if self._on_up:
            self._on_up(self.local_ip, self.peer_ip)
