"""modem.py - drive the PC's modem: dial tone, DTMF detection, answer.

The AT sequence is the one randnetpi3.py uses on Linux. Nothing in it is
Linux specific: it is the modem's command set, not the OS's. What differs on
Windows is what happens after CONNECT. Linux closes the port and hands it to
pppd; here the port stays open and PPP runs in this process.

A USB modem shows up as a COM port once its driver is installed. A softmodem
(an HSF/HCF/AMR card or the RJ11 jack on an older laptop) does too: its
Windows driver presents a virtual COM port that takes AT commands like any
other modem. In Device Manager it is under Modems; the port is on the
Advanced tab of its properties.
"""

import logging
import math
import struct
import time

logger = logging.getLogger("randnet-win.modem")

DLE = 0x10
ETX = 0x03
DTMF_CHARS = "0123456789ABCD*#"



def synthesize_dial_tone(seconds=4.0, rate=8000):
    """350 Hz + 440 Hz, 8 kHz 8 bit unsigned mono: the same as install_randnetpi3.py."""
    frames = int(rate * seconds)
    samples = bytearray(frames)
    for index in range(frames):
        t = float(index) / rate
        mixed = (math.sin(2.0 * math.pi * 350.0 * t)
                 + math.sin(2.0 * math.pi * 440.0 * t)) / 2.0
        samples[index] = max(0, min(255, int(round(mixed * 110.0)) + 128))
    return bytes(samples)


def read_wav_samples(path):
    """Return the PCM payload of a WAV file.

    Looks for the data chunk rather than assuming a 44 byte header, and warns
    when the format is not the 8 kHz 8 bit mono the modem is told to expect.
    """
    with open(path, "rb") as handle:
        data = handle.read()
    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise ValueError("%s is not a RIFF/WAVE file" % path)
    offset = 12
    fmt = None
    while offset + 8 <= len(data):
        chunk, size = data[offset:offset + 4], struct.unpack("<I", data[offset + 4:offset + 8])[0]
        body = data[offset + 8:offset + 8 + size]
        if chunk == b"fmt " and len(body) >= 16:
            fmt = struct.unpack("<HHIIHH", body[:16])
        elif chunk == b"data":
            if fmt and (fmt[0], fmt[1], fmt[2], fmt[5]) != (1, 1, 8000, 8):
                logger.warning("%s is not 8 kHz 8 bit mono PCM (format %r); the "
                               "dial tone will sound wrong", path, fmt)
            return body
        offset += 8 + size + (size & 1)
    raise ValueError("%s has no data chunk" % path)


# ---------------------------------------------------------------- encodings
#
# The dial tone is kept as 8 bit unsigned PCM (what dreampi's WAV holds) and
# converted to whatever the modem was told to expect with AT+VSM. Compression
# ids 0-127 are standardised by ITU-T V.253; 128 and up are vendor specific.

ENCODINGS = ("u8", "s16le", "s16be", "ulaw", "alaw")
V253_CMID = {0: "s16le", 1: "u8", 4: "ulaw", 5: "alaw"}
BYTES_PER_SAMPLE = {"u8": 1, "s16le": 2, "s16be": 2, "ulaw": 1, "alaw": 1}


def ulaw_byte(sample):
    """One 16 bit signed sample to G.711 mu-law."""
    sign = 0x80 if sample < 0 else 0
    if sample < 0:
        sample = -sample
    sample = min(sample, 32635) + 0x84
    exponent = 7
    mask = 0x4000
    while not sample & mask and exponent > 0:
        exponent -= 1
        mask >>= 1
    mantissa = (sample >> (exponent + 3)) & 0x0F
    return ~(sign | (exponent << 4) | mantissa) & 0xFF


_ALAW_SEG_END = (0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF)


def alaw_byte(sample):
    """One 16 bit signed sample to G.711 A-law."""
    value = sample >> 3
    if value >= 0:
        mask = 0xD5
    else:
        mask = 0x55
        value = -value - 1
    segment = 0
    while segment < 8 and value > _ALAW_SEG_END[segment]:
        segment += 1
    if segment >= 8:
        return 0x7F ^ mask
    out = segment << 4
    out |= (value >> 1) & 0x0F if segment < 2 else (value >> segment) & 0x0F
    return out ^ mask


def encode_samples(u8_samples, encoding):
    """Convert 8 bit unsigned PCM to the modem's voice format."""
    if encoding == "u8":
        return bytes(u8_samples)
    linear = [(value - 128) << 8 for value in bytearray(u8_samples)]
    if encoding == "s16le":
        return struct.pack("<%dh" % len(linear), *linear)
    if encoding == "s16be":
        return struct.pack(">%dh" % len(linear), *linear)
    if encoding == "ulaw":
        return bytes(bytearray(ulaw_byte(v) for v in linear))
    if encoding == "alaw":
        return bytes(bytearray(alaw_byte(v) for v in linear))
    raise ValueError("unknown voice encoding %r" % encoding)


def encoding_for(sample_mode, override="auto"):
    """The encoding to send for AT+VSM=<sample_mode>."""
    override = (override or "auto").strip().lower()
    if override != "auto":
        if override not in ENCODINGS:
            raise ValueError("voice_encoding must be auto or one of %s, got %r"
                             % (", ".join(ENCODINGS), override))
        return override
    try:
        cmid = int(sample_mode.split(",")[0])
    except (ValueError, AttributeError):
        cmid = 1
    if cmid in V253_CMID:
        return V253_CMID[cmid]
    logger.warning("AT+VSM compression id %d is vendor specific; assuming 8 bit "
                   "unsigned PCM. Set modem.voice_encoding if the tone is wrong.",
                   cmid)
    return "u8"


def classify_vsm_entry(cmid, name, bits):
    """Map one AT+VSM=? line to an encoding this bridge can produce, or None."""
    label = name.upper().replace(" ", "")
    if "711U" in label or "ULAW" in label or "U-LAW" in label:
        return "ulaw"
    if "711A" in label or "ALAW" in label or "A-LAW" in label:
        return "alaw"
    if "ADPCM" in label:
        return None
    if bits == 8 and ("UNSIGNED" in label or cmid == 1 or "LINEAR" in label):
        return "u8"
    if bits == 16 and "PCM" in label:
        return "s16le"
    known = V253_CMID.get(cmid)
    if known and bits == 8 * BYTES_PER_SAMPLE[known]:
        return known
    return None


PREFERENCE = ("u8", "ulaw", "alaw", "s16le")


def analyse_probe(replies):
    """Turn --probe answers into a verdict.

    replies: {command: text the modem returned}. Returns (ok, lines,
    suggested settings dict).
    """
    import re
    lines = []
    ok = True
    settings = {}

    classes = replies.get("AT+FCLASS=?", "")
    class_list = []
    for line in classes.splitlines():
        line = line.strip()
        if line and line not in ("OK", "ERROR") and not line.startswith("AT"):
            class_list += [part.strip() for part in line.split(",")]
    has_voice = any(part.split(".")[0] == "8" for part in class_list)
    set8 = replies.get("AT+FCLASS=8", "")
    if has_voice and "ERROR" not in set8:
        lines.append("voice mode (class 8): yes")
    else:
        ok = False
        lines.append("voice mode (class 8): NO. AT+FCLASS=? lists %s%s."
                     % (",".join(class_list) or "nothing",
                        " and AT+FCLASS=8 answers ERROR" if "ERROR" in set8 else ""))
        lines.append("  The bridge needs class 8 to play the dial tone and hear "
                     "the console's digits. With this driver it cannot work.")
        lines.append("  Without voice mode, answer_mode = ring still works if a "
                     "line simulator supplies the dial tone and rings this "
                     "modem (see the README).")
        if re.search(r"\d+,\"", replies.get("AT+VSM=?", "")):
            lines.append("  The modem does list voice formats (AT+VSM=?), so the "
                         "voice engine is there but disabled: a driver build "
                         "with voice/TAM support usually turns it on.")

    formats = []
    for cmid, name, bits, rate in re.findall(
            r'(\d+)\s*,\s*"([^"]*)"\s*,\s*(\d+)\s*,\s*\d+\s*,\s*(\d+)',
            replies.get("AT+VSM=?", "")):
        encoding = classify_vsm_entry(int(cmid), name, int(bits))
        formats.append((int(cmid), name, int(bits), int(rate), encoding))
    usable = [f for f in formats if f[4] and f[3] == 8000]
    if usable:
        best = sorted(usable, key=lambda f: PREFERENCE.index(f[4]))[0]
        settings["voice_sample_mode"] = "%d,8000" % best[0]
        settings["voice_encoding"] = best[4]
        lines.append('voice format: use %d "%s" -> voice_sample_mode = %d,8000, '
                     "voice_encoding = %s" % (best[0], best[1], best[0], best[4]))
    elif formats:
        ok = False
        lines.append("voice format: none of the AT+VSM=? formats is one this "
                     "bridge can send (8 bit linear, mu-law, A-law or 16 bit PCM "
                     "at 8000 Hz)")
    else:
        lines.append("voice format: AT+VSM=? gave no formats")
        ok = False
    return ok, lines, settings


def dle_escape(data):
    """In voice mode a DLE byte in the audio must be sent twice (V.253)."""
    return data.replace(bytes([DLE]), bytes([DLE, DLE]))


def decode_dtmf(raw):
    if not raw:
        return None
    try:
        char = raw.decode("ascii").upper()
    except (UnicodeDecodeError, AttributeError):
        return None
    return char if char in DTMF_CHARS else None


class TonePacer(object):
    """Hands out audio in real time so the modem's buffer neither starves
    nor overflows. Same pacing as the Linux version."""

    CHUNK = 1000
    RATE = 8000

    def __init__(self, data, clock=time.monotonic, bytes_per_second=None):
        self._data = data
        self._clock = clock
        self._interval = float(self.CHUNK) / (bytes_per_second or self.RATE)
        self._offset = 0
        self._deadline = None

    def start(self):
        self._offset = 0
        self._deadline = self._clock()

    def due(self):
        return self._deadline is not None and self._clock() >= self._deadline

    def next_chunk(self):
        chunk = self._data[self._offset:self._offset + self.CHUNK]
        self._offset += self.CHUNK
        if self._offset >= len(self._data):
            self._offset = 0
        now = self._clock()
        self._deadline += self._interval
        if self._deadline < now:
            self._deadline = now + self._interval
        return chunk


class Modem(object):
    VALID_RESPONSES = (b"OK", b"ERROR", b"CONNECT", b"VCON", b"NO CARRIER")

    def __init__(self, device, speed, tone_samples, sample_mode="1,8000",
                 init_commands=(), rtscts=False, encoding="auto"):
        self.device = device
        self.speed = int(speed)
        self.sample_mode = sample_mode
        self.encoding = encoding_for(sample_mode, encoding)
        tone_samples = encode_samples(tone_samples, self.encoding)
        self.init_commands = [c for c in init_commands if c]
        self.rtscts = rtscts
        self.serial = None
        self._sending_tone = False
        self._pacer = TonePacer(
            tone_samples, bytes_per_second=8000 * BYTES_PER_SAMPLE[self.encoding])
        self.connect_line = ""

    @property
    def is_open(self):
        return self.serial is not None

    def open(self):
        import serial

        if self.serial:
            self.close()
        logger.info("Opening %s at %d baud%s", self.device, self.speed,
                    " with RTS/CTS" if self.rtscts else "")
        self.serial = serial.Serial(self.device, self.speed, timeout=0,
                                    write_timeout=10, rtscts=self.rtscts)
        self.serial.dtr = True

    def close(self):
        if not self.serial:
            return
        try:
            self.serial.close()
        except Exception:
            logger.exception("Error closing %s", self.device)
        self.serial = None
        logger.info("Closed %s", self.device)

    def write(self, data):
        self.serial.write(data)

    def read_available(self):
        waiting = self.serial.in_waiting
        return self.serial.read(waiting) if waiting else b""

    @property
    def carrier(self):
        try:
            return bool(self.serial.cd)
        except Exception:
            return True

    def drain_input(self):
        try:
            self.serial.reset_input_buffer()
        except Exception:
            pass

    def send_command(self, command, timeout=10.0, ignore_responses=()):
        """Send one AT command and wait for a final result code."""
        if self.serial is None:
            raise IOError("modem port is not open")
        expected = [r for r in self.VALID_RESPONSES if r not in ignore_responses]
        if isinstance(command, str):
            command = command.encode("ascii")
        self.drain_input()
        self.serial.write(command + b"\r")
        logger.debug("-> %s", command.decode("ascii", "replace"))

        deadline = time.monotonic() + timeout
        buffered = b""
        while True:
            chunk = self.read_available()
            if chunk:
                buffered += chunk
                for line in buffered.split(b"\r"):
                    line = line.strip()
                    for resp in expected:
                        if line.startswith(resp):
                            logger.debug("<- %s", buffered.strip().decode(
                                "ascii", "replace").replace("\r\n", " | "))
                            if resp == b"CONNECT":
                                self.connect_line = line.decode("ascii", "replace")
                            return resp
            if time.monotonic() > deadline:
                raise IOError("timed out waiting for a response to %s (got %r)"
                              % (command.decode("ascii", "replace"),
                                 buffered.strip()[-80:]))
            time.sleep(0.005)

    def query(self, command, timeout=3.0):
        """Send a command and return everything the modem said, for --probe."""
        self.drain_input()
        self.serial.write(command.encode("ascii") + b"\r")
        deadline = time.monotonic() + timeout
        buffered = b""
        while time.monotonic() < deadline:
            chunk = self.read_available()
            if chunk:
                buffered += chunk
                tail = buffered.strip().split(b"\n")[-1].strip()
                if tail in (b"OK", b"ERROR"):
                    break
            else:
                time.sleep(0.01)
        return buffered.decode("ascii", "replace")

    def send_escape(self):
        time.sleep(1.1)
        self.serial.write(b"+++")
        time.sleep(1.1)

    def reset(self):
        self.send_command("ATZ0")
        self.send_command("ATE0")
        for command in self.init_commands:
            if self.send_command(command) != b"OK":
                logger.warning("The modem answered ERROR to %s", command)

    @property
    def sending_tone(self):
        return self._sending_tone

    def start_dial_tone(self):
        """Voice mode, and play the tone. The console dials over it in DTMF."""
        self.reset()
        steps = ("AT+FCLASS=8", "AT+VLS=1", "AT+VSM=%s" % self.sample_mode, "AT+VTX")
        for command in steps:
            ignore = (b"OK",) if command == "AT+VTX" else ()
            result = self.send_command(command, ignore_responses=ignore)
            if result == b"ERROR" and command == "AT+FCLASS=8":
                raise IOError(
                    "the modem refused AT+FCLASS=8: it has no voice mode with "
                    "its current driver, so it cannot play the dial tone or "
                    "hear the console dial. Run --probe for details.")
            if result == b"ERROR":
                raise IOError(
                    "the modem refused %s. It may not support voice mode, or "
                    "may want a different sample format: run with --probe and "
                    "set modem.voice_sample_mode to one AT+VSM=? lists"
                    % command)
        self._pacer.start()
        self._sending_tone = True
        logger.info("Listening for a call")

    def stop_dial_tone(self):
        if not self._sending_tone:
            return
        # The same sequence as randnetpi3.py: end the transmit with DLE ETX,
        # escape to command mode, hang up, reset.
        self.serial.write(b"\x00" + bytes([DLE, ETX]) + b"\r\n")
        self._sending_tone = False
        self.send_escape()
        self.send_command("ATH0", timeout=5)
        self.reset()

    def pump_dial_tone(self):
        if not self._sending_tone or not self._pacer.due():
            return False
        self.serial.write(dle_escape(self._pacer.next_chunk()))
        return True

    def read_byte(self):
        return self.serial.read(1)

    def wait_for_ring(self, should_stop, rings=1):
        """Data-mode answering: wait for the modem to report RING.

        Needs no voice mode, so it works on modems whose driver has none.
        Something else on the line must then provide the dial tone and ring
        this modem when the console dials: a line simulator, not a plain
        voltage inducer. Returns True on the wanted ring, False when stopped.
        """
        self.reset()
        self.send_command("AT+FCLASS=0")
        self.send_command("ATS0=0")
        logger.info("Listening for a call (data mode: waiting for the line to "
                    "ring)")
        buffered = b""
        count = 0
        while not should_stop():
            chunk = self.read_available()
            if not chunk:
                time.sleep(0.05)
                continue
            buffered += chunk
            while b"RING" in buffered:
                buffered = buffered.split(b"RING", 1)[1]
                count += 1
                logger.info("RING %d of %d", count, rings)
                if count >= rings:
                    return True
            buffered = buffered[-8:]
        return False

    def answer(self, timeout=60.0):
        self.reset()
        result = self.send_command("ATA", timeout=timeout,
                                   ignore_responses=(b"OK",))
        if result != b"CONNECT":
            raise IOError("ATA ended with %s instead of CONNECT"
                          % result.decode("ascii"))
        logger.info("Call answered: %s", self.connect_line)

    def hang_up(self):
        try:
            self.send_escape()
            self.send_command("ATH0", timeout=5)
        except Exception as exc:
            logger.debug("ATH0 after +++ failed (%s); dropping DTR", exc)
            try:
                self.serial.dtr = False
                time.sleep(1.0)
                self.serial.dtr = True
            except Exception:
                pass
