"""dnsserver.py - the console's DNS, standing in for dnsmasq.

Answers the Randnet names with the configured server address (what the
dnsmasq drop-in does on Linux), and everything else either by forwarding the
raw query to an upstream server, when one is configured, or through the PC's
own resolver. The second way needs no configuration and follows whatever DNS
Windows is using, including its hosts file, but can only answer A records.
"""

import logging
import socket
import struct

logger = logging.getLogger("randnet-win.dns")

TYPE_A = 1
TYPE_AAAA = 28
TYPE_ANY = 255
CLASS_IN = 1

RCODE_OK, RCODE_FORMERR, RCODE_SERVFAIL, RCODE_NXDOMAIN = 0, 1, 2, 3


def parse_query(data):
    """Return (id, flags, name, qtype, qclass, question_bytes) or None."""
    if len(data) < 12:
        return None
    ident, flags, qdcount = struct.unpack("!HHH", data[:6])
    if flags & 0x8000 or qdcount < 1:
        return None
    labels = []
    offset = 12
    while True:
        if offset >= len(data):
            return None
        length = data[offset]
        if length & 0xC0:
            return None
        offset += 1
        if length == 0:
            break
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
        if len(labels) > 127:
            return None
    if offset + 4 > len(data):
        return None
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    question = data[12:offset + 4]
    return ident, flags, ".".join(labels).lower(), qtype, qclass, question


def build_response(query, addresses, rcode=RCODE_OK, ttl=60):
    ident, flags, _name, qtype, _qclass, question = query
    answers = b""
    count = 0
    if rcode == RCODE_OK and qtype in (TYPE_A, TYPE_ANY):
        for address in addresses[:8]:
            answers += struct.pack("!HHHIH", 0xC00C, TYPE_A, CLASS_IN, ttl, 4)
            answers += socket.inet_aton(address)
            count += 1
    out_flags = 0x8000 | (flags & 0x7900) | 0x0080 | (rcode & 0x0F)
    return struct.pack("!HHHHHH", ident, out_flags, 1, count, 0, 0) + question + answers


def build_error(data, rcode):
    if len(data) < 12:
        return None
    ident, flags = struct.unpack("!HH", data[:4])
    return struct.pack("!HHHHHH", ident, 0x8000 | (flags & 0x7900) | 0x0080 | rcode,
                       0, 0, 0, 0)


def resolve_a(name):
    infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
    found = []
    for info in infos:
        address = info[4][0]
        if address not in found:
            found.append(address)
    return found


class DnsResponder(object):
    """handle(query, reply) answers now or later through stack.results."""

    def __init__(self, overrides, domain, target_ip, stack_results, submit,
                 upstream=None, timeout=4.0):
        self.overrides = set(name.lower().rstrip(".") for name in overrides or ())
        self.domain = (domain or "").lower().strip(".")
        self.target_ip = target_ip
        self.results = stack_results
        self.submit = submit
        self.upstream = upstream
        self.timeout = timeout

    def override_for(self, name):
        if not self.target_ip:
            return None
        name = name.lower().rstrip(".")
        if name in self.overrides:
            return self.target_ip
        if self.domain and (name == self.domain or name.endswith("." + self.domain)):
            return self.target_ip
        return None

    def handle(self, data, reply):
        query = parse_query(data)
        if query is None:
            error = build_error(data, RCODE_FORMERR)
            if error:
                reply(error)
            return
        name, qtype = query[2], query[3]

        target = self.override_for(name)
        if target:
            logger.info("DNS %s -> %s (Randnet redirect)", name, target)
            reply(build_response(query, [target] if qtype in (TYPE_A, TYPE_ANY)
                                 else [], ttl=0))
            return

        if self.upstream:
            self._defer(self._forward, data, query, reply)
        else:
            self._defer(self._resolve, data, query, reply)

    def _defer(self, func, data, query, reply):
        def work():
            try:
                answer = func(data, query)
            except Exception as exc:
                logger.debug("DNS %s failed: %s", query[2], exc)
                answer = build_response(query, [], RCODE_SERVFAIL)
            if answer is not None:
                self.results.put(("call", lambda: reply(answer)))
        self.submit(work)

    def _resolve(self, data, query):
        name, qtype = query[2], query[3]
        if qtype not in (TYPE_A, TYPE_ANY):
            return build_response(query, [])
        try:
            addresses = resolve_a(name)
        except socket.gaierror as exc:
            logger.info("DNS %s -> not found (%s)", name, exc)
            return build_response(query, [], RCODE_NXDOMAIN)
        logger.info("DNS %s -> %s", name, ", ".join(addresses) or "nothing")
        return build_response(query, addresses)

    def _forward(self, data, query):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.sendto(data, (self.upstream, 53))
            while True:
                answer, _ = sock.recvfrom(4096)
                if answer[:2] == data[:2]:
                    logger.info("DNS %s -> forwarded to %s", query[2], self.upstream)
                    return answer
        finally:
            sock.close()
