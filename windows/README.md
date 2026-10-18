# randnet_win — the Randnet bridge on Windows

The Windows version of randnetpi3. It answers the N64's call on the PC's own
modem (a USB modem, or the RJ11 softmodem built into an older PC), checks the
CHAP key, and gives the console the same network the Linux bridge gives it:
the Randnet names redirected, the browsing proxy in the path, and the
optional TLS tunnel to the Randnet server.

## How it differs from the Linux version

On Linux the work is split across pppd, iptables, dnsmasq and stunnel. Windows
has none of these, and its own dial-in server (Incoming Connections / RAS)
cannot be used: it only answers a ringing line, and the console never rings
it. It dials DTMF digits over a dial tone the bridge has to play.

So everything runs in one Python process, with no admin rights and no
drivers beyond the modem's own:

| Linux | Windows |
|---|---|
| `pppd` | `ppp.py`: LCP, CHAP-MD5, IPCP, with the same options as the Linux peers file |
| kernel routing + iptables NAT | `netstack.py`: a userspace NAT, like slirp. The console's connections become ordinary sockets on the PC |
| dnsmasq | `dnsserver.py`: answers the Randnet names, everything else through Windows' own resolver |
| stunnel | Python's `ssl`, checked against the Windows certificate store |
| `randnet_proxy.py` as a service | the same file from the folder above, run in-process on loopback |

The modem side (`modem.py`) sends the same AT sequence as `randnetpi3.py`:
voice mode, dial tone, wait for a DTMF digit, `ATA`.

## What you need

- Windows with Python 3.4 or newer, and `pyserial`:
  `py -m pip install -r requirements.txt`. For Windows XP, which stops at
  Python 3.4, use [`../windows-xp`](../windows-xp/README.md).
- `dial-tone.wav` from [dreampi](https://github.com/Kazade/dreampi), set as
  `dial_tone_wav` in the config. The tone generated without it did not get a
  console to dial in testing.
- A modem with **voice mode** (`AT+FCLASS=8`) that reports DTMF digits. A USB
  modem that works with the Linux version should work here; it is the same
  modem command set. Install the modem's driver; the modem then appears in
  Device Manager under *Modems*, with its COM port on the *Advanced* tab of
  its properties.
- A softmodem works when its Windows driver offers voice/TAM (answering
  machine) support. The driver presents a COM port like any modem. Two
  things can stop it: no driver for your Windows version, or a driver with
  no voice mode. `--probe` tells you which.
- The phone cable from the N64 modem to the PC's modem, as on Linux. If your
  modem will not answer on a line with no voltage, it needs a line voltage
  inducer between the two, the same as a DreamPi setup.

## Quick start

1. Copy the whole `randnetpi3-main` folder to the PC. The bridge loads
   `randnet_proxy.py` from the folder above this one, or from its own
   folder if you copy it there.
2. Find the modem:
   ```
   py randnet_win.py --list-ports
   ```
3. Check it can do voice mode:
   ```
   py randnet_win.py --config randnet_win.conf --probe
   ```
   `AT+FCLASS=?` must include `8`. `AT+VSM=?` lists the sample formats: set
   `voice_sample_mode` to the 8-bit unsigned linear PCM one at 8000 Hz.
   `1,8000` (the default, the same as Linux) suits Conexant/Rockwell chips.
   `--probe` prints the two lines to put in the config.
   (An earlier version of this README said Agere chips want `128,8000`. That
   was a guess; an Agere SoftModem 2.1.20 lists no such format, and takes
   `4,8000` with `voice_encoding = ulaw`.)
4. Edit `randnet_win.conf`: set `device` (e.g. `COM3`) if it was not
   auto-detected, and `chap_secret` to your disk's key (see the main README,
   *Finding your CHAP key*).
5. Check the plan, then start:
   ```
   py randnet_win.py --config randnet_win.conf --dry-run
   start_randnet.bat
   ```
6. Wait for `Listening for a call`, then cold boot the console and dial.

A successful call logs `Heard DTMF digit`, `Call answered: CONNECT ...`,
`CHAP authentication succeeded`, `IPCP open`, then the console's DNS lookups
and connections, one line each.

To start it with Windows, add `start_randnet.bat` to Task Scheduler with the
trigger *At log on*.

## Configuration

`randnet_win.conf` uses the same sections and key names as
`randnetpi3.conf` wherever a setting means the same thing. What changed:

| Setting | Notes |
|---|---|
| `[ppp] local_ip`, `peer_ip` | Fixed defaults (`192.168.164.1`/`.2`). The console's traffic leaves from the PC's own address, so these never touch your LAN and no free addresses have to be found |
| `[modem] voice_sample_mode` | New. The `AT+VSM=` argument; see Quick start |
| `[modem] init_commands` | New. Extra AT commands after every reset, one per line (country code for a softmodem, for instance) |
| `[modem] flow_control` | New. `none` (as on Linux) or `rtscts` |
| `[modem] use_dcd` | New. End the session when DCD drops |
| `[modem] answer_mode`, `answer_rings` | New. `ring` answers in data mode on `RING`, for a modem without voice mode. Needs a telephone line simulator that plays the dial tone and rings the PC; see `../windows-xp/README.md` |
| `[network] upstream_dns` | New. Forward other queries to this server instead of using Windows' resolver |
| `[network] ca_file` | New. Extra CA bundle for the tunnel and the proxy, for an out-of-date Windows certificate store |
| `[proxy]` | New. The browsing proxy's options, which the Linux installer passes on its command line |
| `randnet_tls` | Defaults to `yes` in the template, with `randnet_redirect = dd.randnetdd.ch`: the Linux TL;DR setup |
| pppd, iptables, dnsmasq and `/etc/hosts` settings | Gone; nothing to configure |

## Commands

```
py randnet_win.py --list-ports          serial ports Windows knows
py randnet_win.py -c FILE --probe       what the modem supports
py randnet_win.py -c FILE --dry-run     addresses and routing, then exit
py randnet_win.py -c FILE               run (Ctrl+C stops)
py randnet_win.py -c FILE --verbose     log every AT command and PPP decision
py randnet_win.py --self-test           offline checks, no modem needed
```

## Security notes

- The browsing proxy listens on **127.0.0.1 only**. On Linux it has to bind
  every interface and rely on the firewall; here the console's connections
  reach it from inside the process, so it is not an open proxy on your LAN.
- The console can reach whatever the PC can reach, your LAN included, as it
  can on Linux.
- The CHAP key is stored in plain text in `randnet_win.conf`. Keep the file
  readable only by your account if the PC is shared.
- With `randnet_tls = no`, the service traffic, credentials included,
  crosses the internet in plain HTTP.

## Known differences

- Pings are answered only for `local_ip`. Pings to other addresses are
  dropped, because forwarding them would need raw sockets and admin rights.
- DNS over TCP to the console's DNS servers is refused; UDP is served.
- Without `upstream_dns`, only address (A) lookups get answers. Other record
  types get an empty reply.
- IP fragments from the console are dropped.
- WRP (`--with-wrp`) and `--check-dns` from the Linux version are not ported.

## Testing

`--self-test` runs offline checks and a full session with a scripted console:
LCP, CHAP, IPCP, DNS, ping, and a 120 KB TCP transfer with 4% of packets to
the console dropped.

`tests/pppd_docker_test.sh` checks the bridge against Debian's `pppd` as the
client, over TCP in place of the modem (`--test-listen`). It runs on macOS or
Linux with Docker, not on Windows.

Neither test covers the modem, so neither touches Windows itself or a real
N64. What they cover: the PPP negotiation, CHAP, IPCP, DNS, routing, the
proxy, the TLS tunnel, and TCP integrity under loss.
