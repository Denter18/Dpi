"""Telegram через WebSocket: обход блокировки MTProto-трафика.

Серверы Telegram (149.154.x.x, 91.108.x.x) режутся по сигнатуре MTProto, а
веб-версия Telegram ходит на `kws<N>.web.telegram.org/apiws` по обычному
TLS+WebSocket. Поток байт у обоих один и тот же (obfuscated2), поэтому мост
просто упаковывает его в бинарные кадры WebSocket.

Номер дата-центра берётся из первых 64 байт потока: они зашифрованы AES-256-CTR
ключом, который лежит в них же (схема obfuscated2 из MTProxy). Для этого здесь
есть маленькая реализация AES (нужна только для 4 блоков).
"""

import base64
import ipaddress
import os
import struct

_NETS = (
    "149.154.160.0/20",
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
    "91.105.192.0/23",
    "185.76.151.0/24",
    "95.161.64.0/20",
)
TG_NETS = [ipaddress.ip_network(n) for n in _NETS]

TG_PORTS = (443, 80, 5222)

# Запасные имена веб-клиента, если kwsN недоступен.
FALLBACK_NAMES = {1: "pluto", 2: "venus", 3: "aurora", 4: "vesta", 5: "flora"}


def is_telegram_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    return ip.version == 4 and any(ip in net for net in TG_NETS)


def ws_hosts(dc: int, media: bool):
    """Имена хостов WebSocket-шлюза для дата-центра, по убыванию приоритета."""
    hosts = []

    if media:
        hosts.append(f"kws{dc}-1.web.telegram.org")

    hosts.append(f"kws{dc}.web.telegram.org")

    if dc in FALLBACK_NAMES:
        hosts.append(f"{FALLBACK_NAMES[dc]}.web.telegram.org")

    return hosts


# --- AES-256 (только шифрование блока) ---------------------------------


def _xtime(a):
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


def _build_sbox():
    sbox = [0] * 256
    p = q = 1

    while True:
        # p *= 3, q /= 3 в поле GF(2^8)
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09

        x = q
        for sh in (1, 2, 3, 4):
            x ^= ((q << sh) | (q >> (8 - sh))) & 0xFF

        sbox[p] = (x ^ 0x63) & 0xFF

        if p == 1:
            break

    sbox[0] = 0x63
    return sbox


SBOX = _build_sbox()


def _expand_key(key: bytes):
    w = [list(key[4 * i : 4 * i + 4]) for i in range(8)]
    rcon = 1

    for i in range(8, 60):
        t = list(w[i - 1])

        if i % 8 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]

        w.append([a ^ b for a, b in zip(w[i - 8], t)])

    return [sum(w[4 * r : 4 * r + 4], []) for r in range(15)]


def _encrypt_block(round_keys, block: bytes) -> bytes:
    s = [b ^ k for b, k in zip(block, round_keys[0])]

    for r in range(1, 15):
        s = [SBOX[b] for b in s]
        s = [s[((c + row) % 4) * 4 + row] for c in range(4) for row in range(4)]

        if r < 14:
            out = []

            for c in range(4):
                a0, a1, a2, a3 = s[4 * c : 4 * c + 4]
                out += [
                    _xtime(a0) ^ _xtime(a1) ^ a1 ^ a2 ^ a3,
                    a0 ^ _xtime(a1) ^ _xtime(a2) ^ a2 ^ a3,
                    a0 ^ a1 ^ _xtime(a2) ^ _xtime(a3) ^ a3,
                    _xtime(a0) ^ a0 ^ a1 ^ a2 ^ _xtime(a3),
                ]

            s = out

        s = [a ^ b for a, b in zip(s, round_keys[r])]

    return bytes(s)


def aes256_ctr_keystream(key: bytes, iv: bytes, length: int) -> bytes:
    rks = _expand_key(key)
    counter = int.from_bytes(iv, "big")
    out = bytearray()

    while len(out) < length:
        out += _encrypt_block(rks, counter.to_bytes(16, "big"))
        counter = (counter + 1) & ((1 << 128) - 1)

    return bytes(out[:length])


def parse_obfuscated_init(init: bytes):
    """(dc, media) из первых 64 байт obfuscated2 или None, если это не он."""
    if len(init) < 64:
        return None

    ks = aes256_ctr_keystream(init[8:40], init[40:56], 64)
    plain = bytes(a ^ b for a, b in zip(init[:64], ks))

    if plain[56:60] not in (b"\xef\xef\xef\xef", b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd"):
        return None

    dc = struct.unpack("<h", plain[60:62])[0]

    if not 1 <= abs(dc) <= 5:
        return None

    return abs(dc), dc < 0


# --- WebSocket ----------------------------------------------------------


def _mask(data: bytes, key: bytes) -> bytes:
    n = len(data)

    if n == 0:
        return b""

    m = (key * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(m, "big")).to_bytes(n, "big")


def build_frame(payload: bytes, opcode: int = 2) -> bytes:
    """Кадр клиента (маскированный) с FIN=1."""
    n = len(payload)
    head = bytearray([0x80 | opcode])

    if n < 126:
        head.append(0x80 | n)
    elif n < 65536:
        head.append(0x80 | 126)
        head += struct.pack("!H", n)
    else:
        head.append(0x80 | 127)
        head += struct.pack("!Q", n)

    key = os.urandom(4)
    return bytes(head) + key + _mask(payload, key)


class WebSocket:
    """Минимальный клиент WebSocket поверх уже открытого (TLS) соединения."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer

    async def handshake(self, host: str, path: str = "/apiws"):
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Protocol: binary\r\n"
            "Origin: https://web.telegram.org\r\n"
            "User-Agent: Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36\r\n\r\n"
        )
        self.writer.write(request.encode("ascii"))
        await self.writer.drain()

        head = await self.reader.readuntil(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0]

        if b" 101" not in status:
            raise OSError("WebSocket: " + status[:60].decode("latin1"))

    def send(self, data: bytes):
        self.writer.write(build_frame(data))

    async def recv(self):
        """Следующая порция данных или None, если соединение закрыто."""
        while True:
            b1, b2 = await self.reader.readexactly(2)
            opcode = b1 & 0x0F
            length = b2 & 0x7F

            if length == 126:
                (length,) = struct.unpack("!H", await self.reader.readexactly(2))
            elif length == 127:
                (length,) = struct.unpack("!Q", await self.reader.readexactly(8))

            key = await self.reader.readexactly(4) if b2 & 0x80 else None
            payload = await self.reader.readexactly(length) if length else b""

            if key:
                payload = _mask(payload, key)

            if opcode == 0x8:
                return None

            if opcode == 0x9:  # ping
                self.writer.write(build_frame(payload, 0xA))
                await self.writer.drain()
                continue

            if opcode == 0xA:  # pong
                continue

            if payload:
                return payload

    def close(self):
        try:
            self.writer.write(build_frame(b"", 0x8))
        except Exception:
            pass

        try:
            self.writer.close()
        except Exception:
            pass
