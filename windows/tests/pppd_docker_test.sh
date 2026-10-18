#!/bin/sh
# pppd_docker_test.sh - check the Windows bridge against a real pppd.
#
# The self-test plays the console with a client written alongside the bridge,
# so it shares the bridge's assumptions. This runs Debian's pppd as the client
# instead: an independent PPP, CHAP and TCP/IP implementation. No modem is
# involved; the bridge's --test-listen mode carries PPP over TCP.
#
# Needs Docker with a kernel that has PPP (Docker Desktop does) and runs on
# macOS or Linux, not Windows. Uses ports 5555, 8000 and 8080 on loopback.
#
#   sh windows/tests/pppd_docker_test.sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
WIN=$(dirname "$HERE")
WORK=$(mktemp -d)
PYTHON=${PYTHON:-python3}
trap 'kill $BRIDGE $HTTP 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"' EXIT

cat > "$WORK/Dockerfile" <<'EOF'
FROM debian:12
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    ppp curl dnsutils netcat-openbsd iproute2 iputils-ping >/dev/null
EOF
docker build -q -t randnet-win-pppd-test "$WORK" >/dev/null || exit 1

cat > "$WORK/test.conf" <<'EOF'
[network]
randnet_redirect = example.com
randnet_tls = yes
[ppp]
lcp_echo_interval = 10
EOF
head -c 1000000 /dev/urandom > "$WORK/big.bin"
WANT=$($PYTHON -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$WORK/big.bin")

(cd "$WORK" && exec $PYTHON -m http.server 8000 --bind 127.0.0.1 >/dev/null 2>&1) &
HTTP=$!
$PYTHON "$WIN/randnet_win.py" --config "$WORK/test.conf" \
    --test-listen 127.0.0.1:5555 > "$WORK/bridge.log" 2>&1 &
BRIDGE=$!
sleep 3

cat > "$WORK/client.sh" <<'EOF'
#!/bin/sh
echo 'n64 Randnet K1QU0K@N *' > /etc/ppp/chap-secrets
pppd nodetach noauth user n64 remotename Randnet local nocrtscts noipdefault \
    usepeerdns lcp-echo-interval 5 lcp-echo-failure 3 \
    pty "nc host.docker.internal 5555" >/dev/null 2>&1 &
for i in $(seq 1 20); do ip addr show ppp0 2>/dev/null | grep -q 'inet ' && break; sleep 1; done
HOSTIP=$(getent ahostsv4 host.docker.internal | head -1 | cut -d' ' -f1)
GW=$(ip route | awk '/^default/ {print $3; exit}')
ip route add "$HOSTIP" via "$GW" dev eth0
ip route replace default dev ppp0
echo "nameserver 192.168.164.1" > /etc/resolv.conf
r() { printf '%s|%s\n' "$1" "$2"; }
r address  "$(ip -4 -o addr show ppp0 | awk '{print $4}')"
r dns_hard "$(dig +short +time=5 @172.16.10.30 www.randnet.ne.jp | head -1)"
r dns_name "$(dig +short +time=5 example.org | head -1)"
r ping     "$(ping -c 2 -W 3 192.168.164.1 >/dev/null && echo ok)"
r hello    "$(curl -s -m 20 http://172.16.10.40:8080/hello | head -1)"
r web      "$(curl -s -m 40 -o /dev/null -w '%{http_code}' http://example.org/)"
r tunnel   "$(curl -s -m 40 -o /dev/null -w '%{http_code}' -H 'Host: example.com' http://www.randnet.ne.jp/)"
curl -s -m 120 -o /tmp/big.bin http://192.168.164.1:8000/big.bin
r bulk     "$(sha256sum /tmp/big.bin | cut -d' ' -f1)"
r server   "$(dig +short +time=5 www.randnet.ne.jp | head -1)"
EOF
docker run --rm --privileged -v "$WORK:/t" randnet-win-pppd-test sh /t/client.sh > "$WORK/out.txt" 2>&1

SERVER=$(grep -o 'Randnet names -> [0-9.]*' "$WORK/bridge.log" | awk '{print $4}')
FAIL=0
expect() {
    got=$(grep "^$1|" "$WORK/out.txt" | cut -d'|' -f2-)
    if [ "$got" = "$2" ]; then echo "  ok   $1"; else
        echo "  FAIL $1: got '$got', want '$2'"; FAIL=1; fi
}
expect address  "192.168.164.2"
expect dns_hard "$SERVER"
expect ping     "ok"
expect hello    "Hello from the Randnet proxy."
expect web      "200"
expect tunnel   "200"
expect bulk     "$WANT"
expect server   "$SERVER"
grep -q '^dns_name|[0-9]' "$WORK/out.txt" && echo "  ok   dns_name" || { echo "  FAIL dns_name"; FAIL=1; }
if [ $FAIL -ne 0 ]; then
    echo; echo "bridge log:"; tail -40 "$WORK/bridge.log"
    echo "(A tunnel failure with CERTIFICATE_VERIFY_FAILED on macOS means this"
    echo " Python has no CA bundle: set SSL_CERT_FILE=/etc/ssl/cert.pem.)"
fi
exit $FAIL
