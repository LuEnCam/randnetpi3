"""win_selftest.py - offline checks for the Windows bridge.

No modem, no admin rights, no internet. The end-to-end part plays the console:
a scripted PPP client negotiates LCP, answers the CHAP challenge, takes an
address over IPCP, then uses DNS, ICMP and TCP through the real Bridge
session loop, with packets towards the console dropped at random so the
retransmission paths run too.

  python randnet_win.py --self-test
"""

import configparser
import hashlib
import logging
import os
import queue
import random
import socket
import struct
import threading
import time

import dnsserver
import modem as modem_mod
import netstack
import ppp
import randnet_win

FAILURES = []


def check(name, got, want):
    if got == want:
        print("  ok   %s" % name)
    else:
        print("  FAIL %s\n         got:  %r\n         want: %r" % (name, got, want))
        FAILURES.append(name)



class MemoryLink(object):
    """The serial line, as two queues. Thread safe."""

    def __init__(self):
        self.to_console = queue.Queue()
        self.to_bridge = queue.Queue()
        self.closed = False

    def write(self, data):
        self.to_console.put(bytes(data))

    def read_available(self):
        chunks = []
        while True:
            try:
                chunks.append(self.to_bridge.get_nowait())
            except queue.Empty:
                break
        return b"".join(chunks)

    @property
    def carrier(self):
        return not self.closed


class FakeConsole(object):
    """Just enough of a PPP client and TCP/IP stack to exercise the bridge."""

    def __init__(self, link, secret, loss=0.0, seed=1):
        self.link = link
        self.secret = secret
        self.decoder = ppp.HdlcDecoder()
        self.rng = random.Random(seed)
        self.loss = loss
        self.lcp_ident = 0
        self.lcp_options = [
            (ppp.LCP_MRU, struct.pack(">H", 1500)),
            (ppp.LCP_ACCM, b"\x00\x00\x00\x00"),
            (ppp.LCP_MAGIC, b"\x12\x34\x56\x78"),
            (ppp.LCP_PFC, b""),
            (ppp.LCP_ACFC, b""),
        ]
        self.ipcp_options = [
            (ppp.IPCP_ADDRESS, b"\x00\x00\x00\x00"),
            (ppp.IPCP_COMPRESSION, b"\x00\x2d\x0f\x01"),
            (ppp.IPCP_DNS1, b"\x00\x00\x00\x00"),
        ]
        self.lcp_acked = self.lcp_peer_acked = False
        self.chap_result = None
        self.ipcp_acked = self.ipcp_peer_acked = False
        self.my_ip = None
        self.dns_ip = None
        self.peer_options = None
        self.ip_inbox = []
        self.lcp_inbox = []
        self.dropped = 0

    def send(self, protocol, info):
        self.link.to_bridge.put(ppp.hdlc_encode(protocol, info))

    def send_lcp_request(self):
        self.lcp_ident += 1
        self.send(ppp.PROTO_LCP, ppp.build_packet(
            ppp.CONF_REQ, self.lcp_ident, ppp.build_options(self.lcp_options)))

    def send_ipcp_request(self):
        self.send(ppp.PROTO_IPCP, ppp.build_packet(
            ppp.CONF_REQ, 1, ppp.build_options(self.ipcp_options)))

    @property
    def ip_up(self):
        return self.ipcp_acked and self.ipcp_peer_acked

    def pump(self, timeout=0.05):
        try:
            data = self.link.to_console.get(timeout=timeout)
        except queue.Empty:
            return
        for frame in self.decoder.feed(data):
            protocol, info = ppp.split_frame(frame)
            self.handle(protocol, info)

    def handle(self, protocol, info):
        code, ident, data = ppp.parse_packet(info) if protocol != ppp.PROTO_IP \
            else (None, None, info)
        if protocol == ppp.PROTO_LCP:
            self.lcp_inbox.append((code, ident, data))
            if code == ppp.CONF_REQ:
                self.peer_options = ppp.parse_options(data)
                self.send(ppp.PROTO_LCP, ppp.build_packet(ppp.CONF_ACK, ident, data))
                self.lcp_peer_acked = True
            elif code == ppp.CONF_ACK:
                self.lcp_acked = True
            elif code == ppp.CONF_REJ:
                rejected = [k for k, _ in ppp.parse_options(data)]
                self.lcp_options = [(k, v) for k, v in self.lcp_options
                                    if k not in rejected]
                self.send_lcp_request()
            elif code == ppp.TERM_REQ:
                self.send(ppp.PROTO_LCP, ppp.build_packet(ppp.TERM_ACK, ident))
        elif protocol == ppp.PROTO_CHAP:
            if code == ppp.CHAP_CHALLENGE:
                challenge = data[1:1 + data[0]]
                value = ppp.chap_md5(ident, self.secret, challenge)
                self.send(ppp.PROTO_CHAP, ppp.build_packet(
                    ppp.CHAP_RESPONSE, ident, bytes([16]) + value + b"n64"))
            elif code == ppp.CHAP_SUCCESS:
                self.chap_result = "success"
                self.send_ipcp_request()
            elif code == ppp.CHAP_FAILURE:
                self.chap_result = "failure"
        elif protocol == ppp.PROTO_IPCP:
            if code == ppp.CONF_REQ:
                self.send(ppp.PROTO_IPCP, ppp.build_packet(ppp.CONF_ACK, ident, data))
                self.ipcp_peer_acked = True
            elif code == ppp.CONF_REJ:
                rejected = [k for k, _ in ppp.parse_options(data)]
                self.ipcp_options = [(k, v) for k, v in self.ipcp_options
                                     if k not in rejected]
                self.send_ipcp_request()
            elif code == ppp.CONF_NAK:
                suggested = dict(ppp.parse_options(data))
                self.ipcp_options = [(k, suggested.get(k, v))
                                     for k, v in self.ipcp_options]
                self.send_ipcp_request()
            elif code == ppp.CONF_ACK:
                self.ipcp_acked = True
                options = dict(ppp.parse_options(data))
                self.my_ip = ppp.ip_text(options[ppp.IPCP_ADDRESS])
                if ppp.IPCP_DNS1 in options:
                    self.dns_ip = ppp.ip_text(options[ppp.IPCP_DNS1])
        elif protocol == ppp.PROTO_IP:
            if self.loss and self.rng.random() < self.loss:
                self.dropped += 1
                return
            self.ip_inbox.append(info)

    def wait(self, predicate, seconds=10.0):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return True
            self.pump()
        return predicate()

    def send_ip(self, packet):
        self.send(ppp.PROTO_IP, packet)

    def take_ip(self, proto):
        for index, packet in enumerate(self.ip_inbox):
            parsed = netstack.parse_ipv4(packet)
            if parsed and parsed["proto"] == proto:
                del self.ip_inbox[index]
                return parsed
        return None

    def tcp_fetch(self, dst, dport, request, seconds=60.0):
        """Open a connection, send request, read until FIN. Returns
        (bytes, outcome) where outcome is 'fin' or 'rst' or 'timeout'."""
        sport = self.rng.randint(20000, 60000)
        iss = self.rng.randint(0, 0xFFFFFFFF)
        src = self.my_ip

        def seg(flags, seq, ack, data=b""):
            self.send_ip(netstack.build_tcp(src, dst, sport, dport, seq, ack,
                                            flags, 8192, data,
                                            mss=1460 if flags & netstack.TCP_SYN else None))

        def next_tcp(deadline):
            while time.monotonic() < deadline:
                parsed = self.take_ip(netstack.IPPROTO_TCP)
                if parsed:
                    tcp = netstack.parse_tcp(parsed["payload"])
                    if tcp["dport"] == sport:
                        return tcp
                    continue
                self.pump()
            return None

        deadline = time.monotonic() + seconds
        syn_sent_at = time.monotonic()
        seg(netstack.TCP_SYN, iss, 0)
        while True:
            tcp = next_tcp(min(deadline, syn_sent_at + 1.0))
            if tcp is None:
                if time.monotonic() >= deadline:
                    return b"", "timeout"
                syn_sent_at = time.monotonic()
                seg(netstack.TCP_SYN, iss, 0)
                continue
            if tcp["flags"] & netstack.TCP_RST:
                return b"", "rst"
            if tcp["flags"] & netstack.TCP_SYN and tcp["flags"] & netstack.TCP_ACK:
                break
        rcv_nxt = netstack.seq_add(tcp["seq"], 1)
        snd = netstack.seq_add(iss, 1)
        seg(netstack.TCP_ACK | netstack.TCP_PSH, snd, rcv_nxt, request)
        req_end = netstack.seq_add(snd, len(request))
        req_acked = False
        req_sent_at = time.monotonic()
        received = bytearray()
        while time.monotonic() < deadline:
            tcp = next_tcp(min(deadline, time.monotonic() + 0.5))
            if tcp is None:
                if not req_acked and time.monotonic() - req_sent_at > 1.0:
                    seg(netstack.TCP_ACK | netstack.TCP_PSH, snd, rcv_nxt, request)
                    req_sent_at = time.monotonic()
                continue
            if tcp["flags"] & netstack.TCP_RST:
                return bytes(received), "rst"
            if tcp["flags"] & netstack.TCP_ACK and tcp["ack"] == req_end:
                req_acked = True
            if tcp["seq"] == rcv_nxt:
                received += tcp["data"]
                rcv_nxt = netstack.seq_add(rcv_nxt, len(tcp["data"]))
                if tcp["flags"] & netstack.TCP_FIN:
                    rcv_nxt = netstack.seq_add(rcv_nxt, 1)
                    seg(netstack.TCP_ACK | netstack.TCP_FIN, req_end, rcv_nxt)
                    fin_deadline = time.monotonic() + 5
                    while time.monotonic() < fin_deadline:
                        tcp = next_tcp(fin_deadline)
                        if tcp and tcp["ack"] == netstack.seq_add(req_end, 1):
                            return bytes(received), "fin"
                        seg(netstack.TCP_ACK | netstack.TCP_FIN, req_end, rcv_nxt)
                    return bytes(received), "fin-unacked"
            if tcp["data"] or tcp["flags"] & netstack.TCP_FIN:
                seg(netstack.TCP_ACK, req_end if req_acked else snd, rcv_nxt)
        return bytes(received), "timeout"



def make_cfg(**network):
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read_dict(randnet_win.DEFAULTS)
    cfg.set("network", "randnet_redirect", "10.20.30.40")
    cfg.set("ppp", "lcp_echo_interval", "0")
    for key, value in network.items():
        cfg.set("network", key, value)
    return cfg


def start_payload_server(payload):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)

    def serve():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            with conn:
                request = conn.recv(1024)
                if request.startswith(b"ECHO "):
                    conn.sendall(request[5:])
                else:
                    conn.sendall(payload)

    threading.Thread(target=serve, daemon=True).start()
    return listener


class _Stop(object):
    stop = False


def run_session_in_thread(bridge, link):
    stopper = _Stop()
    result = {}

    def target():
        result["reason"] = bridge.run_session(link, stopper)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return stopper, thread, result



def test_framing():
    print("HDLC framing")
    check("RFC 1662 good-FCS constant",
          ppp.fcs16(b"\x01\x02\x03" + struct.pack("<H", ppp.fcs16(b"\x01\x02\x03") ^ 0xFFFF)),
          ppp.FCS_GOOD)
    frame = ppp.hdlc_encode(ppp.PROTO_LCP, bytes(range(40)) + b"\x7e\x7d")
    check("every control byte escaped",
          any(b < 0x20 for b in frame[1:-1]), False)
    decoder = ppp.HdlcDecoder()
    frames = decoder.feed(frame)
    check("round trip", ppp.split_frame(frames[0]),
          (ppp.PROTO_LCP, bytes(range(40)) + b"\x7e\x7d"))
    damaged = bytearray(frame)
    damaged[10] ^= 0x01
    check("bad FCS dropped", decoder.feed(bytes(damaged)), [])
    check("bad FCS counted", decoder.bad_fcs, 1)
    check("modem text between frames ignored",
          len(decoder.feed(b"\r\nCONNECT 33600\r\n" + frame)), 1)
    check("compressed protocol field", ppp.split_frame(b"\x21abc"), (0x21, b"abc"))
    check("ACFC (no FF 03)", ppp.split_frame(b"\xc0\x21xy"), (0xC021, b"xy"))
    split = decoder.feed(frame[:7]) + decoder.feed(frame[7:])
    check("frame split across reads", len(split), 1)
    check("CHAP MD5 matches RFC 1994 construction",
          ppp.chap_md5(7, "K1QU0K@N", b"abc"),
          hashlib.md5(b"\x07K1QU0K@Nabc").digest())


def test_checksums():
    print("IP and TCP")
    packet = netstack.build_tcp("192.168.164.2", "10.0.0.1", 1234, 80, 1, 2,
                                netstack.TCP_SYN, 1000, b"", mss=1460)
    check("IP header checksum verifies", netstack.checksum(packet[:20]), 0)
    tcp = packet[20:]
    check("TCP checksum verifies",
          netstack.checksum(netstack.pseudo_header("192.168.164.2", "10.0.0.1",
                                                   6, len(tcp)) + tcp), 0)
    parsed = netstack.parse_tcp(tcp)
    check("MSS option parsed", parsed["mss"], 1460)
    check("sequence wraps", netstack.seq_diff(5, 0xFFFFFFFE), 7)
    check("sequence negative", netstack.seq_diff(0xFFFFFFFE, 5), -7)
    udp = netstack.build_udp("1.2.3.4", "5.6.7.8", 53, 999, b"hello")
    check("UDP checksum verifies",
          netstack.checksum(netstack.pseudo_header("1.2.3.4", "5.6.7.8", 17,
                                                   len(udp) - 20) + udp[20:]), 0)


def test_dns():
    print("DNS")
    results = queue.Queue()
    responder = dnsserver.DnsResponder(
        ["www.randnet.ne.jp"], "randnet.ne.jp", "10.20.30.40", results,
        lambda func: func())
    query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + \
        b"\x03www\x07randnet\x02ne\x02jp\x00" + struct.pack("!HH", 1, 1)
    replies = []
    responder.handle(query, replies.append)
    reply = replies[0]
    check("override id echoed", reply[:2], b"\x12\x34")
    check("override has one answer", struct.unpack("!H", reply[6:8])[0], 1)
    check("override address", socket.inet_ntoa(reply[-4:]), "10.20.30.40")
    check("wildcard under the domain",
          responder.override_for("mail.dd.randnet.ne.jp"), "10.20.30.40")
    check("look-alike domain not matched",
          responder.override_for("notrandnet.ne.jp"), None)
    off = dnsserver.DnsResponder([], "randnet.ne.jp", None, results, None)
    check("no target means no override", off.override_for("randnet.ne.jp"), None)


def test_modem_helpers():
    print("modem helpers")
    check("DLE doubled in audio", modem_mod.dle_escape(b"\x01\x10\x02"),
          b"\x01\x10\x10\x02")
    check("DTMF digit", modem_mod.decode_dtmf(b"5"), "5")
    check("DTMF lower case hex", modem_mod.decode_dtmf(b"a"), "A")
    check("not DTMF", modem_mod.decode_dtmf(b"s"), None)
    tone = modem_mod.synthesize_dial_tone(seconds=0.5)
    check("tone length", len(tone), 4000)
    check("synthetic tone never contains DLE", 0x10 in tone, False)
    import tempfile
    header = b"RIFF" + struct.pack("<I", 36 + len(tone)) + b"WAVEfmt " + \
        struct.pack("<IHHIIHH", 16, 1, 1, 8000, 8000, 1, 8) + b"data" + \
        struct.pack("<I", len(tone))
    handle = tempfile.NamedTemporaryFile(delete=False, suffix=".wav")
    try:
        handle.write(header + tone)
        handle.close()
        check("wav payload found by chunk", modem_mod.read_wav_samples(handle.name), tone)
    finally:
        os.unlink(handle.name)


AGERE_PROBE = {
    # Real --probe output from an Agere SoftModem 2.1.20 on Windows XP.
    "AT+FCLASS=?": "0,1\r\nOK\r\n",
    "AT+FCLASS=8": "ERROR\r\n",
    "AT+VSM=?": '0,"Signed PCM",16,0,8000,(0,122-148),0\r\n'
                '4,"G.711U",8,0,8000,(0,122-148),0\r\n'
                '5,"G.711A",8,0,8000,(0,122-148),0\r\n'
                '132,"IMA ADPCM",4,0,8000,(0,122-148),0\r\nOK\r\n',
}


def test_voice_formats():
    print("voice formats")
    check("mu-law of silence", modem_mod.ulaw_byte(0), 0xFF)
    check("A-law of silence", modem_mod.alaw_byte(0), 0xD5)
    check("mu-law full scale positive", modem_mod.ulaw_byte(32767), 0x80)
    check("mu-law full scale negative", modem_mod.ulaw_byte(-32768), 0x00)
    try:
        import audioop
    except ImportError:
        audioop = None
    if audioop is not None:
        linear = struct.pack("<%dh" % 512, *range(-32768, 32768, 128))
        check("mu-law matches audioop",
              bytes(bytearray(modem_mod.ulaw_byte(v) for v in
                              struct.unpack("<512h", linear))),
              audioop.lin2ulaw(linear, 2))
        check("A-law matches audioop",
              bytes(bytearray(modem_mod.alaw_byte(v) for v in
                              struct.unpack("<512h", linear))),
              audioop.lin2alaw(linear, 2))
    check("u8 -> s16le", modem_mod.encode_samples(b"\x80\xff\x00", "s16le"),
          b"\x00\x00\x00\x7f\x00\x80")
    check("V.253 id 4 is mu-law", modem_mod.encoding_for("4,8000"), "ulaw")
    check("id 1 stays 8 bit unsigned", modem_mod.encoding_for("1,8000"), "u8")
    check("explicit override wins", modem_mod.encoding_for("1,8000", "alaw"), "alaw")
    pacer = modem_mod.TonePacer(b"\x00" * 4000, clock=lambda: 0.0,
                                bytes_per_second=16000)
    check("16 bit audio paced at 16000 bytes/s", pacer._interval, 1000 / 16000.0)

    ok, lines, settings = modem_mod.analyse_probe(AGERE_PROBE)
    check("Agere without class 8 is rejected", ok, False)
    check("  and the voice format is still worked out", settings,
          {"voice_sample_mode": "4,8000", "voice_encoding": "ulaw"})
    fixed = dict(AGERE_PROBE, **{"AT+FCLASS=?": "0,1,8\r\nOK\r\n",
                                 "AT+FCLASS=8": "OK\r\n"})
    check("Agere with class 8 is accepted", modem_mod.analyse_probe(fixed)[0], True)
    rockwell = {"AT+FCLASS=?": "0,1,1.0,2,8\r\nOK", "AT+FCLASS=8": "OK",
                "AT+VSM=?": '1,"UNSIGNED PCM",8,0,8000,0,0\r\n'
                            '129,"IMA ADPCM",4,0,8000,0,0\r\nOK'}
    check("Rockwell picks 1,8000 unsigned",
          modem_mod.analyse_probe(rockwell)[2],
          {"voice_sample_mode": "1,8000", "voice_encoding": "u8"})


class ScriptedSerial(object):
    """A modem that says OK to everything, CONNECT to ATA, and rings when
    told to."""

    def __init__(self, rings_after=3):
        self.inbox = bytearray()
        self.sent = []
        self.rings_after = rings_after
        self.rang = False

    @property
    def in_waiting(self):
        # Ring only once the commands are answered and read, like a real
        # call arriving while the bridge waits.
        if not self.inbox and not self.rang and len(self.sent) >= self.rings_after:
            self.rang = True
            self.inbox += b"\r\nRING\r\n\r\nRING\r\n"
        return len(self.inbox)

    def read(self, count=1):
        data = bytes(self.inbox[:count])
        del self.inbox[:count]
        return data

    def reset_input_buffer(self):
        del self.inbox[:]

    def write(self, data):
        command = bytes(data).strip()
        self.sent.append(command)
        if command == b"ATA":
            self.inbox += b"\r\nCONNECT 33600\r\n"
        else:
            self.inbox += b"\r\nOK\r\n"


def test_ring_mode():
    print("data-mode answering (answer_mode = ring)")
    line = modem_mod.Modem("COM3", 57600, b"\x80" * 8000)
    line.serial = ScriptedSerial(rings_after=4)
    check("waits for the second ring",
          line.wait_for_ring(lambda: False, rings=2), True)
    check("voice mode never requested",
          any(b"FCLASS=8" in c or b"VTX" in c for c in line.serial.sent), False)
    check("auto-answer kept off", b"ATS0=0" in line.serial.sent, True)
    line.answer(timeout=2)
    check("answered with ATA", line.connect_line, "CONNECT 33600")
    stopped = modem_mod.Modem("COM3", 57600, b"\x80" * 8000)
    stopped.serial = ScriptedSerial(rings_after=99)
    check("stop request ends the wait",
          stopped.wait_for_ring(lambda: True), False)


def test_router():
    print("routing (the iptables rules of randnetpi3.py)")
    cfg = make_cfg(randnet_tls="yes", randnet_tls_host="dd.example.test",
                   proxy_target_port="8080")
    router = randnet_win.Router(cfg, "10.20.30.40", "192.168.164.1", {"192.168.1.50"})
    check("proxy host", router("172.16.10.40", 8080)[:3], ("tcp", "127.0.0.1", 8080))
    check("Randnet server port 80 goes through TLS",
          router("10.20.30.40", 80)[:3], ("tls", "dd.example.test", 443))
    check("Randnet server other ports direct",
          router("10.20.30.40", 110)[:3], ("tcp", "10.20.30.40", 110))
    check("any other port 80 to the proxy",
          router("93.184.215.14", 80)[:3], ("tcp", "127.0.0.1", 8080))
    check("this end of the link is this PC",
          router("192.168.164.1", 8080)[:3], ("tcp", "127.0.0.1", 8080))
    check("this PC's LAN address not proxied",
          router("192.168.1.50", 80)[:3], ("tcp", "192.168.1.50", 80))
    check("other ports direct", router("93.184.215.14", 443)[:3],
          ("tcp", "93.184.215.14", 443))
    check("DNS over TCP refused", router("172.16.10.30", 53).kind, "refuse")
    plain = randnet_win.Router(make_cfg(transparent_http="no"), "10.20.30.40",
                               "192.168.164.1", set())
    check("transparent off passes port 80 through",
          plain("93.184.215.14", 80)[:3], ("tcp", "93.184.215.14", 80))
    check("TLS off sends the server's port 80 direct",
          plain("10.20.30.40", 80)[:3], ("tcp", "10.20.30.40", 80))
    no_host = randnet_win.Router(make_cfg(randnet_redirect="host", randnet_tls="yes"),
                                 "192.168.1.50", "192.168.164.1", set())
    check("TLS needs a server name", no_host.tls, False)


def test_port_detection():
    print("modem port detection")
    order = randnet_win.port_candidates(
        [("COM3", "HSF Data Fax Voice Modem")],
        [("COM1", "Communications Port (COM1)"), ("COM5", "USB Modem")],
        [("COM1", r"\Device\Serial0"), ("COM3", r"\Device\HSFi"),
         ("COM7", r"\Device\Winachsf0")])
    check("installed modem first, motherboard UART last",
          [port for port, _ in order], ["COM3", "COM5", "COM7", "COM1"])

    class FakeWinreg(object):
        HKEY_LOCAL_MACHINE = "HKLM"
        tree = {
            randnet_win.MODEM_CLASS_KEY: ["0000", "0001", "Properties"],
            randnet_win.MODEM_CLASS_KEY + "\\0000": {
                "AttachedTo": "COM3", "FriendlyName": "HSF Data Fax Voice Modem"},
            randnet_win.MODEM_CLASS_KEY + "\\0001": {
                "AttachedTo": "", "DriverDesc": "Bluetooth modem"},
        }

        def OpenKey(self, parent, name):
            path = name if parent == "HKLM" else parent + "\\" + name
            if path not in self.tree:
                raise OSError("access denied")
            return path

        def EnumKey(self, key, index):
            try:
                return self.tree[key][index]
            except IndexError:
                raise OSError("no more")

        def EnumValue(self, key, index):
            items = sorted(self.tree[key].items())
            if index >= len(items):
                raise OSError("no more")
            return items[index] + (1,)

    saved = randnet_win.winreg_mod, randnet_win.os.name
    randnet_win.winreg_mod = FakeWinreg
    randnet_win.os.name = "nt"
    try:
        found = randnet_win.windows_modems()
    finally:
        randnet_win.winreg_mod, randnet_win.os.name = saved
    check("modem read from the Modem device class",
          found, [("COM3", "HSF Data Fax Voice Modem")])


def test_session():
    print("end to end: a scripted console through the real session loop")
    saved = netstack.RTO_BASE
    netstack.RTO_BASE = 0.25
    payload = bytes(random.Random(7).getrandbits(8) for _ in range(120000))
    server = start_payload_server(payload)
    port = server.getsockname()[1]
    try:
        bridge = randnet_win.Bridge(make_cfg())
        link = MemoryLink()
        stopper, thread, result = run_session_in_thread(bridge, link)
        console = FakeConsole(link, "K1QU0K@N", loss=0.04)
        console.send_lcp_request()
        check("LCP opens", console.wait(lambda: console.lcp_acked and console.lcp_peer_acked), True)
        offered = dict(console.peer_options or [])
        check("server demands CHAP-MD5", offered.get(ppp.LCP_AUTH), b"\xc2\x23\x05")
        check("PFC and ACFC were rejected",
              [k for k, _ in console.lcp_options], [ppp.LCP_MRU, ppp.LCP_ACCM, ppp.LCP_MAGIC])
        console.wait(lambda: console.chap_result)
        check("CHAP succeeds", console.chap_result, "success")
        check("IPCP opens", console.wait(lambda: console.ip_up), True)
        check("console address assigned", console.my_ip, "192.168.164.2")
        check("DNS server assigned", console.dns_ip, "192.168.164.1")
        check("VJ compression rejected",
              ppp.IPCP_COMPRESSION in dict(console.ipcp_options), False)

        console.send(0x8057, b"\x01\x01\x00\x04")
        check("unknown protocol gets Protocol-Reject",
              console.wait(lambda: any(c == ppp.PROTO_REJ for c, _, _ in console.lcp_inbox)),
              True)

        console.loss = 0.0
        query = struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + \
            b"\x03www\x07randnet\x02ne\x02jp\x00" + struct.pack("!HH", 1, 1)
        console.send_ip(netstack.build_udp(console.my_ip, "172.16.10.30", 5353, 53, query))
        answer = []
        console.wait(lambda: answer.append(console.take_ip(netstack.IPPROTO_UDP)) or
                     answer[-1] is not None)
        reply = answer[-1]
        check("DNS to the disk's hard-coded server is answered", reply is not None, True)
        if reply:
            check("  from the address it was sent to", reply["src"], "172.16.10.30")
            check("  with the Randnet server", socket.inet_ntoa(reply["payload"][-4:]),
                  "10.20.30.40")

        echo = b"\x08\x00\x00\x00\x00\x01\x00\x01pingdata"
        echo = echo[:2] + struct.pack("!H", netstack.checksum(echo)) + echo[4:]
        console.send_ip(netstack.build_ipv4(console.my_ip, "192.168.164.1", 1, echo))
        pong = []
        console.wait(lambda: pong.append(console.take_ip(netstack.IPPROTO_ICMP)) or
                     pong[-1] is not None)
        check("ping to this end answered", bool(pong[-1]) and pong[-1]["payload"][0], 0)

        console.loss = 0.04
        data, outcome = console.tcp_fetch("192.168.164.1", port, b"GET")
        check("TCP transfer completes with 4% loss", outcome, "fin")
        check("  %d bytes, intact" % len(payload),
              hashlib.sha256(data).hexdigest(), hashlib.sha256(payload).hexdigest())
        check("  some packets really were dropped", console.dropped > 0, True)

        console.loss = 0.0
        data, outcome = console.tcp_fetch("192.168.164.1", port, b"ECHO hello n64")
        check("console's data reaches the upstream", data, b"hello n64")

        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()
        _, outcome = console.tcp_fetch("192.168.164.1", dead_port, b"x", seconds=10)
        check("refused upstream becomes a reset", outcome, "rst")

        link.closed = True
        thread.join(5)
        check("session ends when the line drops", result.get("reason"), "link closed")
    finally:
        server.close()
        netstack.RTO_BASE = saved


def test_bad_key():
    print("end to end: wrong CHAP key")
    bridge = randnet_win.Bridge(make_cfg())
    link = MemoryLink()
    stopper, thread, result = run_session_in_thread(bridge, link)
    console = FakeConsole(link, "WRONGKEY")
    console.send_lcp_request()
    console.wait(lambda: console.chap_result)
    check("CHAP fails", console.chap_result, "failure")
    check("link is terminated",
          console.wait(lambda: any(c == ppp.TERM_REQ for c, _, _ in console.lcp_inbox)),
          True)
    thread.join(10)
    check("session reason", result.get("reason"), "CHAP authentication failed")


def run():
    logging.basicConfig(level=logging.WARNING,
                        format="%(asctime)s %(levelname)-7s %(message)s")
    for test in (test_framing, test_checksums, test_dns, test_modem_helpers, test_voice_formats, test_ring_mode,
                 test_router, test_port_detection, test_session, test_bad_key):
        try:
            test()
        except Exception as exc:
            import traceback
            traceback.print_exc()
            check("%s raised" % test.__name__, repr(exc), "no exception")
    print()
    if FAILURES:
        print("%d check(s) FAILED" % len(FAILURES))
        return 1
    print("all checks passed")
    return 0
