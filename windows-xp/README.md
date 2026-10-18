# randnet_xp — the Randnet bridge on Windows XP

For an older PC with a built-in RJ11 modem. Windows XP can run Python 3.4 at
most, so this version targets Python 3.4. It is the same bridge as
[`../windows`](../windows/README.md), whose code runs on Python 3.4 too. This
folder holds a launcher and a config for the parts XP lacks:

| XP problem | What this folder does |
|---|---|
| Python stops at 3.4 | The bridge avoids newer language features. `randnet_xp.py` refuses anything older than 3.4 |
| pyserial 3.1 and newer crash on XP (`function 'CancelIoEx' not found`: a Vista API) | pyserial **3.0.1** ships in this folder as a wheel and is used as-is, nothing to install. A newer copy in `site-packages` is skipped |
| XP's root certificates are too old for today's servers | `ca_file = cacert.pem` in `randnet_xp.conf`: a current CA bundle for the TLS tunnel and the browsing proxy |
| XP's browsers cannot open most sites any more | Every download below is done on a modern PC and copied over |

PPP, NAT, DNS and TLS run inside the Python process, as on newer Windows. No
admin rights, no drivers beyond the modem's.

## Downloads (on a modern PC)

Put these on a USB stick:

1. **Python 3.4.4** for Windows, `python-3.4.4.msi`, from
   <https://www.python.org/downloads/release/python-344/>. It is the last
   Python release with a Windows XP installer.
2. **cacert.pem**, from <https://curl.se/ca/cacert.pem> (page:
   <https://curl.se/docs/caextract.html>). A bundle of trusted root
   certificates; you download it, you do not create it.
3. Nothing for pyserial: `pyserial-3.0.1-py3-none-any.whl` is already in
   this folder. Do **not** use pyserial 3.5 on XP, it cannot load there.
4. **dial-tone.wav**, from <https://github.com/Kazade/dreampi>.
5. This whole `randnetpi3-main` folder.
6. The **modem driver** for XP, if the modem is not already working. XP was
   the main OS for softmodems, so drivers are usually easy to find. Look for
   the laptop maker's "modem" or "TAM"/"voice" driver package.

## Install (on the XP PC)

1. Run `python-3.4.4.msi`. The default `C:\Python34` is what
   `start_randnet_xp.bat` looks for.
2. Copy `randnetpi3-main` anywhere, for example `C:\randnet`. Keep its
   layout: the launcher needs `..\windows` and `..\randnet_proxy.py`.
3. Copy `cacert.pem` and `dial-tone.wav` into
   `randnetpi3-main\windows-xp`, next to the pyserial wheel already there.
4. Check the PC's **date and time**. Certificate checks fail on a wrong
   clock, and an old PC with a flat CMOS battery often has one.

## Run

From a command prompt in `randnetpi3-main\windows-xp`:

```
C:\Python34\python.exe randnet_xp.py --self-test
C:\Python34\python.exe randnet_xp.py --list-ports
C:\Python34\python.exe randnet_xp.py --probe
```

`--probe` shows whether the modem can do what the bridge needs:

- `AT+FCLASS=?` must include `8` (voice mode).
- `AT+VSM=?` lists the sample formats. `--probe` picks one and prints the
  `voice_sample_mode` and `voice_encoding` lines for `randnet_xp.conf`:
  `1,8000` / `u8` on Conexant/Rockwell (HSF/HCF) chips, `4,8000` / `ulaw` on
  an Agere SoftModem. (An earlier version said `128,8000` for Agere. That
  was a guess and is wrong for the Agere 2.1.20 driver.)

If `AT+FCLASS=?` has no `8`, or `AT+FCLASS=8` answers `ERROR`, the installed
driver has voice turned off and the bridge cannot work with it. If the same
modem still lists formats under `AT+VSM=?`, the voice engine is present: a
driver build for the same chip with voice/TAM ("answering machine") support
usually enables it.

Then edit `randnet_xp.conf`: `device` (the modem's COM port, under *Phone and
Modem Options* > *Modems* > *Properties* > *Advanced*, or from
`--list-ports`), and `chap_secret` (your disk's key). Then:

```
C:\Python34\python.exe randnet_xp.py --dry-run
start_randnet_xp.bat
```

Wait for `Listening for a call`, then cold boot the console and dial. The log
also goes to `randnet_xp.log`.

## A modem without voice mode

Some built-in modems never get voice mode, whatever the driver: an IBM
ThinkPad's Agere AC'97 modem (`PCI\VEN_8086&DEV_2486&SUBSYS_xxxx1014`) on
IBM's driver 2.1.20 is one. For those, set in `randnet_xp.conf`:

```ini
[modem]
answer_mode = ring
```

The bridge then stays in data mode and answers when the modem reports
`RING`. That moves two jobs onto the phone line, so the line needs a
**telephone line simulator** between the N64 and the PC: a box with two
phone sockets that plays a dial tone to the caller and rings the other
socket when a number is dialled. A plain *line voltage inducer* (the usual
DreamPi part) only supplies voltage. It does neither, and will not work in
this mode.

Check the simulator's description for both "dial tone" and "ring". To test
it before the N64, plug two ordinary phones into it: lifting one must give a
dial tone, and dialling any number must ring the other.

The console is fine with this: it dials, the line rings the PC, the PC
answers, and the modems connect exactly as they would on a real exchange.

## Settings specific to this folder

`randnet_xp.conf` is `randnet_win.conf` with two lines filled in:

```ini
[modem]
dial_tone_wav = dial-tone.wav

[network]
ca_file = cacert.pem
```

Relative paths are relative to the config file. Everything else is
described in [`../windows/README.md`](../windows/README.md).

## About the bundled pyserial

`pyserial-3.0.1-py3-none-any.whl` was built unmodified from the official
source release `pyserial-3.0.1.tar.gz` on PyPI (sha256
`969cb6405d1d87f8960cf9c10f597ae58f85da2fb9769dba96f4aeeaade54656`, which
matches PyPI's published digest). pyserial is BSD licensed. 3.0.1 is the
last release before `CancelIoEx` was introduced in 3.1, and it has every
call the bridge uses. It uses only Windows 2000-era kernel32 functions.

## Security notes

Windows XP and Python 3.4 both stopped getting security fixes years ago.
Keep the PC behind a home router and use it for this job only. The bridge
adds little exposure of its own: the browsing proxy listens on 127.0.0.1
only, and nothing else listens on the network. It does fetch web pages on
the console's behalf, with Python 3.4's TLS stack and its OpenSSL 1.0.2.

`cacert.pem` decides which servers are trusted. Download it from curl.se
over HTTPS on a trusted machine, and replace it now and then.

## What was tested, and what was not

Tested on Python 3.4.10 (Linux, Docker), with pyserial loaded from the wheel
file and no pip:

- with a copy that fails like pyserial 3.5 does on XP installed in
  `site-packages` and dropped next to the launcher, the launcher skips both
  and loads 3.0.1; without 3.0.1 it stops with a message naming it
- the modem code's AT exchange against a scripted modem on pyserial 3.0.1

- the self-test
- a real `pppd` client against the bridge, over TCP in place of the modem:
  CHAP, IPCP, DNS, ping, the browsing proxy, and 1 MB down and 400 KB up
  intact with 5% loss and reordering
- OpenSSL 1.0.2 verifying the current certificate chains of
  `dd.randnetdd.ch`, Cloudflare, Wikipedia and Google against `cacert.pem`.
  As a control, all four fail against a bundle with one unrelated root

Not tested: Windows XP itself, its Python 3.4.4 build (it bundles an older
1.0.2 OpenSSL than the one tested), a softmodem, and the modem side as a
whole. That last part is the same code that answered a real N64 on Windows
10 with a Conexant USB modem.
