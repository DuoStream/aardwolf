# SPDX-License-Identifier: MIT
"""Moonlight microphone PCM -> the selected Duo session's RDP AUDIO_INPUT channel."""
import asyncio
import audioop
import ctypes as C
from ctypes import wintypes as W
from dataclasses import dataclass
import json
from pathlib import Path
import struct
import sys
import threading
import time
import winreg
from aardwolf.extensions.RDPEDYC.channel import RDPEDYCChannel
from aardwolf.extensions.RDPEDYC.vchannels import VirtualChannelBase
from aardwolf.extensions.RDPEDYC.protocol import DYNVC_CMD
from aardwolf.extensions.RDPEDYC.protocol.data import DYNVC_DATA_FIRST

class PcmBuffer:
    def __init__(self):
        self.lock = threading.Lock()
        self.raw = bytearray()
        self.converted = bytearray()
        self.rate_state = None
        self.format = None
        self.active = False
        self.last_data = 0.0

    def begin(self, rate, channels):
        with self.lock:
            self.raw.clear(); self.converted.clear(); self.rate_state = None
            self.format = (rate, channels); self.active = True

    def end(self):
        with self.lock:
            self.active = False
            self.raw.clear(); self.converted.clear(); self.rate_state = None

    def clear(self):
        with self.lock:
            self.raw.clear(); self.converted.clear(); self.rate_state = None

    def push(self, data):
        if len(data) % 2:
            raise ValueError('PCM must contain complete 16-bit samples')
        with self.lock:
            self.last_data = time.monotonic()
            if not self.active: return
            self.raw.extend(data)
            # At most 100 ms of fresh source data; stale audio cannot build up
            # while a game pauses or the RDP sink is temporarily not consuming.
            excess = max(0, len(self.raw) - 9600)
            if excess:
                del self.raw[:excess]

    def read(self, frames, rate, channels):
        with self.lock:
            if self.format != (rate, channels):
                self.raw.clear(); self.converted.clear(); self.rate_state = None
                self.format = (rate, channels)
            if not self.active or time.monotonic() - self.last_data > .25:
                self.raw.clear(); self.converted.clear(); self.rate_state = None
                return bytes(frames * channels * 2)
            required = frames * 2
            while len(self.converted) < required and self.raw:
                chunk = bytes(self.raw[:960]); del self.raw[:len(chunk)]
                if rate == 48000:
                    converted = chunk
                else:
                    converted, self.rate_state = audioop.ratecv(chunk, 2, 1, 48000, rate, self.rate_state)
                self.converted.extend(converted)
            mono = bytes(self.converted[:required]); del self.converted[:len(mono)]
            if len(mono) < required:
                mono += bytes(required - len(mono))
                self.rate_state = None
            return mono if channels == 1 else audioop.tostereo(mono, 2, 1, 1)

MAGIC = 0x33434D44
HEADER_BYTES = 64
SLOT_BYTES = 1936
SLOTS = 16
MAPPING_BYTES = HEADER_BYTES + SLOT_BYTES * SLOTS
MASK = 0xFFFFFFFF


class RingReader:
    def __init__(self): self.sequence = 0
    def pull(self, memory, now_ms, clock=None):
        latest, writer = struct.unpack_from('<II', memory, 16)
        if not writer:
            self.sequence = latest
            return []
        distance = (latest - self.sequence) & MASK
        if distance == 0: return []
        packets = []
        # Use at most the newest 100 ms. A paused game never replays old speech.
        for behind in range(min(distance, 5) - 1, -1, -1):
            sequence = (latest - behind) & MASK
            offset = HEADER_BYTES + (sequence % SLOTS) * SLOT_BYTES
            expected = (sequence * 2 + 2) & MASK
            stamp, frames, tick = struct.unpack_from('<IIQ', memory, offset)
            if stamp != expected or frames != 960:
                continue
            pcm = bytes(memory[offset + 16:offset + SLOT_BYTES])
            current = clock() if clock is not None else now_ms
            if tick > current or current - tick > 250:
                continue
            # Recheck the publication stamp after copying: the slot may have
            # wrapped while the reader was being descheduled.
            if struct.unpack_from('<I', memory, offset)[0] == expected:
                packets.append(pcm)
        self.sequence = latest
        return packets


kernel = C.WinDLL('kernel32', use_last_error=True)
advapi = C.WinDLL('advapi32', use_last_error=True)
wts = C.WinDLL('wtsapi32', use_last_error=True)


class SecurityAttributes(C.Structure):
    _fields_ = [('length', W.DWORD), ('descriptor', C.c_void_p), ('inherit', W.BOOL)]


kernel.CreateFileMappingW.argtypes = [W.HANDLE, C.POINTER(SecurityAttributes), W.DWORD, W.DWORD, W.DWORD, W.LPCWSTR]
kernel.CreateFileMappingW.restype = W.HANDLE
kernel.MapViewOfFile.argtypes = [W.HANDLE, W.DWORD, W.DWORD, W.DWORD, C.c_size_t]
kernel.MapViewOfFile.restype = C.c_void_p
kernel.UnmapViewOfFile.argtypes = [C.c_void_p]
kernel.CloseHandle.argtypes = [W.HANDLE]
kernel.LocalFree.argtypes = [C.c_void_p]
kernel.GetTickCount64.restype = C.c_uint64
kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
kernel.OpenProcess.restype = W.HANDLE
kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
kernel.WaitForSingleObject.restype = W.DWORD
advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [W.LPCWSTR, W.DWORD, C.POINTER(C.c_void_p), C.c_void_p]
advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = W.BOOL
advapi.LookupAccountNameW.argtypes = [W.LPCWSTR, W.LPCWSTR, C.c_void_p, C.POINTER(W.DWORD), W.LPWSTR, C.POINTER(W.DWORD), C.POINTER(W.DWORD)]
advapi.LookupAccountNameW.restype = W.BOOL
advapi.ConvertSidToStringSidW.argtypes = [C.c_void_p, C.POINTER(C.c_void_p)]
advapi.ConvertSidToStringSidW.restype = W.BOOL
wts.WTSQuerySessionInformationW.argtypes = [W.HANDLE, W.DWORD, C.c_int, C.POINTER(C.c_void_p), C.POINTER(W.DWORD)]
wts.WTSQuerySessionInformationW.restype = W.BOOL
wts.WTSFreeMemory.argtypes = [C.c_void_p]


def user_sid(username):
    size, domain_size, sid_type = W.DWORD(), W.DWORD(), W.DWORD()
    advapi.LookupAccountNameW(None, username, None, C.byref(size), None, C.byref(domain_size), C.byref(sid_type))
    if not size.value: raise C.WinError(C.get_last_error())
    sid = C.create_string_buffer(size.value)
    domain = C.create_unicode_buffer(max(1, domain_size.value))
    if not advapi.LookupAccountNameW(None, username, sid, C.byref(size), domain, C.byref(domain_size), C.byref(sid_type)):
        raise C.WinError(C.get_last_error())
    text = C.c_void_p()
    if not advapi.ConvertSidToStringSidW(sid, C.byref(text)): raise C.WinError(C.get_last_error())
    try: return C.wstring_at(text)
    finally: kernel.LocalFree(text)


def instance_session(instance, username):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE\\Duo\\Instances\\' + instance) as key:
            session = winreg.QueryValueEx(key, 'SessionId')[0]
    except OSError: return None
    pointer, size = C.c_void_p(), W.DWORD()
    if not isinstance(session, int) or session <= 0: return None
    if not wts.WTSQuerySessionInformationW(None, session, 5, C.byref(pointer), C.byref(size)): return None
    try: return session if C.wstring_at(pointer).casefold() == username.casefold() else None
    finally: wts.WTSFreeMemory(pointer)


class SharedAudio:
    def __init__(self, instance, username):
        self.instance, self.username = instance, username
        self.buffer = PcmBuffer()
        self.stopping = threading.Event()
        self.worker = threading.Thread(target=self._run, daemon=True)
        self.worker.start()

    def _run(self):
        handle = None; address = None; descriptor = C.c_void_p()
        try:
            sid = user_sid(self.username)
            sddl = 'D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;' + sid + ')'
            if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, C.byref(descriptor), None):
                raise C.WinError(C.get_last_error())
            attributes = SecurityAttributes(C.sizeof(SecurityAttributes), descriptor, False)
            while not self.stopping.is_set():
                session = instance_session(self.instance, self.username)
                if session is not None:
                    C.set_last_error(0)
                    handle = kernel.CreateFileMappingW(W.HANDLE(-1), C.byref(attributes), 4, 0, MAPPING_BYTES,
                                                       'Global\\DuoMic.Sunshine.' + str(session))
                    error = C.get_last_error()
                    if not handle: raise C.WinError(error)
                    if error != 183: break  # Never trust a pre-existing object.
                    kernel.CloseHandle(handle); handle = None
                self.stopping.wait(.2)
            if not handle: return
            address = kernel.MapViewOfFile(handle, 6, 0, 0, MAPPING_BYTES)
            if not address: raise C.WinError(C.get_last_error())
            raw = (C.c_ubyte * MAPPING_BYTES).from_address(address)
            memory = memoryview(raw).cast('B')
            memory[:] = bytes(MAPPING_BYTES)
            struct.pack_into('<III', memory, 4, 3, session, SLOTS)
            struct.pack_into('<Q', memory, 24, kernel.GetTickCount64())
            struct.pack_into('<I', memory, 0, MAGIC)
            reader = RingReader(); last_writer_check = 0
            while not self.stopping.is_set():
                now = kernel.GetTickCount64()
                struct.pack_into('<Q', memory, 24, now)
                for pcm in reader.pull(memory, now, kernel.GetTickCount64):
                    self.buffer.push(pcm)
                writer = struct.unpack_from('<I', memory, 20)[0]
                if not writer: self.buffer.clear()
                if writer and now - last_writer_check > 1000:
                    C.set_last_error(0)
                    process = kernel.OpenProcess(0x00100000, False, writer)
                    error = C.get_last_error()
                    try:
                        dead = (process and kernel.WaitForSingleObject(process, 0) == 0) or (not process and error == 87)
                        if dead and struct.unpack_from('<I', memory, 20)[0] == writer:
                            struct.pack_into('<I', memory, 20, 0)
                    finally:
                        if process: kernel.CloseHandle(process)
                    last_writer_check = now
                self.stopping.wait(.005)
        except OSError:
            pass
        finally:
            self.buffer.end()
            if address: kernel.UnmapViewOfFile(address)
            if handle: kernel.CloseHandle(handle)
            if descriptor: kernel.LocalFree(descriptor)

    def begin(self, rate, channels): self.buffer.begin(rate, channels)
    def end(self): self.buffer.end()
    def read(self, frames, rate, channels): return self.buffer.read(frames, rate, channels)
    def close(self):
        self.stopping.set(); self.worker.join(timeout=2); self.buffer.end()

VERSION, FORMATS, OPEN, OPEN_REPLY, DATA_INCOMING, DATA, FORMAT_CHANGE = range(1, 8)
WAVE = struct.Struct('<HHIIHHH')
MAX_FORMATS = 128
MAX_PDU = 65536


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class AudioFormat:
    tag: int
    channels: int
    rate: int
    bytes_per_second: int
    block_align: int
    bits: int
    extra: bytes = b''

    @classmethod
    def parse(cls, packet, offset):
        if len(packet) - offset < WAVE.size:
            raise ProtocolError('Truncated WAVEFORMATEX')
        fields = WAVE.unpack_from(packet, offset)
        end = offset + WAVE.size + fields[-1]
        if end > len(packet):
            raise ProtocolError('Truncated format extension')
        return cls(*fields[:-1], packet[offset + WAVE.size:end]), end

    def encode(self):
        return WAVE.pack(self.tag, self.channels, self.rate, self.bytes_per_second,
                         self.block_align, self.bits, len(self.extra)) + self.extra

    def supported(self):
        return (self.tag == 1 and self.channels in (1, 2) and self.bits == 16
                and self.rate in (8000, 11025, 16000, 22050, 32000, 44100, 48000)
                and self.block_align == self.channels * 2
                and self.bytes_per_second == self.rate * self.block_align
                and not self.extra)


class AudinProtocol:
    def __init__(self, pcm_provider):
        if not callable(pcm_provider):
            raise ValueError('A microphone PCM provider is required')
        self.pcm_provider = pcm_provider
        self.state = 'version'
        self.formats = []
        self.selected = None
        self.frames_per_packet = 0

    @property
    def audio_format(self):
        return None if self.selected is None else self.formats[self.selected]

    def handle(self, packet):
        if not packet or len(packet) > MAX_PDU:
            raise ProtocolError('Empty or oversized audio control PDU')
        kind = packet[0]
        if kind == VERSION:
            if self.state != 'version' or len(packet) != 5:
                raise ProtocolError('Unexpected or malformed version PDU')
            version, = struct.unpack_from('<I', packet, 1)
            if version not in (1, 2):
                raise ProtocolError('Unsupported audio protocol version')
            self.state = 'formats'
            return [struct.pack('<BI', VERSION, 2)]
        if kind == FORMATS:
            if self.state != 'formats' or len(packet) < 9:
                raise ProtocolError('Unexpected or malformed formats PDU')
            count, _reserved_size = struct.unpack_from('<II', packet, 1)
            if not 1 <= count <= MAX_FORMATS:
                raise ProtocolError('Invalid format count')
            formats = []
            offset = 9
            for _ in range(count):
                fmt, offset = AudioFormat.parse(packet, offset)
                if fmt.supported():
                    formats.append(fmt)
            if offset != len(packet):
                raise ProtocolError('Unexpected trailing format data')
            if not formats:
                raise ProtocolError('Server offered no supported PCM16 format')
            self.formats = formats
            encoded = b''.join(fmt.encode() for fmt in formats)
            self.state = 'open'
            return [bytes([DATA_INCOMING]), struct.pack('<BII', FORMATS, len(formats), 9 + len(encoded)) + encoded]
        if kind == OPEN:
            if self.state != 'open' or len(packet) < 9:
                raise ProtocolError('Unexpected or malformed open PDU')
            frames, index = struct.unpack_from('<II', packet, 1)
            # Some servers append the optional CaptureFormat. Validate it but
            # transmit the negotiated format, not this device-side suggestion.
            if len(packet) > 9:
                _, end = AudioFormat.parse(packet, 9)
                if end != len(packet):
                    raise ProtocolError('Unexpected trailing open data')
            self._select(index)
            if not 1 <= frames <= min(65536, self.audio_format.rate):
                raise ProtocolError('Invalid audio packet frame count')
            self.frames_per_packet = frames
            self.state = 'streaming'
            return [struct.pack('<BI', FORMAT_CHANGE, index), struct.pack('<BI', OPEN_REPLY, 0)]
        if kind == FORMAT_CHANGE:
            if self.state != 'streaming' or len(packet) != 5:
                raise ProtocolError('Unexpected or malformed format change')
            index, = struct.unpack_from('<I', packet, 1)
            self._select(index)
            if self.frames_per_packet > self.audio_format.rate:
                raise ProtocolError('Packet duration exceeds the prototype limit')
            return [struct.pack('<BI', FORMAT_CHANGE, index)]
        raise ProtocolError('Unexpected audio control message')

    def _select(self, index):
        if index >= len(self.formats):
            raise ProtocolError('Invalid negotiated format index')
        self.selected = index

    def next_audio(self):
        if self.state != 'streaming':
            raise ProtocolError('Audio cannot be sent before the server opens the input')
        fmt = self.audio_format
        pcm = self.pcm_provider(self.frames_per_packet, fmt.rate, fmt.channels)
        if not isinstance(pcm, bytes) or len(pcm) != self.frames_per_packet * fmt.block_align:
            raise ProtocolError('PCM provider returned the wrong frame size')
        return [bytes([DATA_INCOMING]), bytes([DATA]) + pcm]

    def close(self):
        self.state = 'closed'

CHANNEL_NAME = 'AUDIO_INPUT'


class AudinChannel(VirtualChannelBase):
    def __init__(self, audio):
        super().__init__(CHANNEL_NAME)
        self.audio = audio
        self.protocol = AudinProtocol(audio.read)
        self.pump = None
        self._fragments = bytearray()
        self._expected = None
        self._manager = None
        self._wire_lock = asyncio.Lock()

    async def channel_init_internal(self, channelid, manager):
        if self.channel_id is not None and not self.channel_closed_evt.is_set():
            return False, RuntimeError('An audio-input channel is already active')
        self._manager = manager
        return await super().channel_init_internal(channelid, manager)

    async def channel_data_out(self, data):
        async with self._wire_lock:
            for fragment in DYNVC_DATA_FIRST.chunk_data(data, self.channel_id):
                ok, error = await self._manager.fragment_and_send(fragment)
                if not ok or error:
                    raise RuntimeError('RDP virtual-channel write failed')

    async def channel_init(self):
        # Aardwolf reuses the named handler when Windows reopens the microphone.
        # Start a new protocol handshake instead of retaining the closed state.
        self.protocol = AudinProtocol(self.audio.read)
        self.channel_closed_evt = asyncio.Event()
        self._fragments.clear(); self._expected = None
        return True, None

    async def channel_rawdata_in(self, msg):
        # The generic upstream reassembler has no size cap. Audio control
        # messages never need unbounded reassembly.
        if msg.cmd == DYNVC_CMD.DATA_FIRST:
            if self._expected is not None or not 1 <= msg.Length <= MAX_PDU:
                await self._fail()
                return
            self._expected = msg.Length
        if len(self._fragments) + len(msg.Data) > MAX_PDU:
            await self._fail()
            return
        self._fragments.extend(msg.Data)
        if self._expected is not None and len(self._fragments) > self._expected:
            await self._fail()
            return
        if self._expected is None or len(self._fragments) == self._expected:
            packet = bytes(self._fragments)
            self._fragments.clear()
            self._expected = None
            await self.channel_data_in(packet)

    async def channel_data_in(self, data):
        try:
            if data and data[0] in (OPEN, FORMAT_CHANGE):
                await self._stop_pump()
            replies = self.protocol.handle(data)
            for reply in replies:
                await self.channel_data_out(reply)
            if self.protocol.state == 'streaming' and self.pump is None:
                fmt = self.protocol.audio_format
                self.audio.begin(fmt.rate, fmt.channels)
                self.pump = asyncio.create_task(self._pump())
        except ProtocolError:
            await self._fail()

    async def _pump(self):
        deadline = asyncio.get_running_loop().time()
        try:
            while not self.channel_closed_evt.is_set():
                for packet in self.protocol.next_audio():
                    await self.channel_data_out(packet)
                period = self.protocol.frames_per_packet / self.protocol.audio_format.rate
                now = asyncio.get_running_loop().time()
                deadline = max(deadline + period, now)
                await asyncio.sleep(max(0, deadline - now))
        except asyncio.CancelledError:
            raise
        except Exception:
            self.audio.end()
            self.protocol.close()

    async def _stop_pump(self):
        if self.pump is not None:
            self.pump.cancel()
            await asyncio.gather(self.pump, return_exceptions=True)
            self.pump = None

    async def _fail(self):
        await self._stop_pump()
        self.protocol.close()
        await self.close_channel()

    async def channel_closed(self):
        await self._stop_pump()
        self.audio.end()
        self.protocol.close()
        await super().channel_closed()

def load_profile(username):
    # Optional existing DuoMic-Rdp.json beside the helper executable:
    # {"schemaVersion":1,"profiles":{"user":{"enabled":true,
    #   "source":"moonlight","instanceName":"Instance"}}}
    program = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
    path = Path(program).resolve().parent / 'DuoMic-Rdp.json'
    try:
        settings = json.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError):
        return None
    if not isinstance(settings, dict) or settings.get('schemaVersion') != 1:
        return None
    profiles = settings.get('profiles')
    if not isinstance(profiles, dict):
        return None
    profile = profiles.get(username.casefold())
    if not isinstance(profile, dict) or profile.get('enabled') is not True:
        return None
    instance = profile.get('instanceName')
    if profile.get('source') != 'moonlight' or not isinstance(instance, str):
        return None
    if not instance.strip() or len(instance) > 255 or any(c in instance for c in ('\\', '/', '\0')):
        return None
    return profile


def configure_microphone(settings, username):
    profile = load_profile(username)
    if profile is None:
        return None
    audio = SharedAudio(profile['instanceName'], username)
    microphone = AudinChannel(audio)
    settings.channels = [RDPEDYCChannel]
    settings.vchannels = {CHANNEL_NAME: microphone}
    settings.audio_capture = True
    return microphone
