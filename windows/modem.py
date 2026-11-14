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

    def __init__(self, data, clock=time.monotonic):
        self._data = data
        self._clock = clock
        self._interval = float(self.CHUNK) / self.RATE
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
                 init_commands=(), rtscts=False):
        self.device = device
        self.speed = int(speed)
        self.sample_mode = sample_mode
        self.init_commands = [c for c in init_commands if c]
        self.rtscts = rtscts
        self.serial = None
        self._sending_tone = False
        self._pacer = TonePacer(tone_samples)
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
