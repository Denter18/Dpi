"""VPN-режим: весь трафик устройства -> движок NoDPI, без root и без внешних библиотек.

Как это работает
----------------
Java-сервис (NoDpiVpnService) поднимает TUN-интерфейс с адресом TUN_ADDR и
маршрутом 0.0.0.0/0 и отдаёт его файловый дескриптор сюда.

* TCP. Приложение (10.111.222.1:sport -> D:dp) шлёт пакеты в TUN. Мы читаем их
  и переписываем адреса так, будто это входящее соединение от фиктивного узла
  PEER_ADDR на локальный сервер движка (TUN_ADDR:lport), после чего пишем пакет
  обратно в TUN. Ядро само ведёт оба конца TCP (клиент приложения и наш
  сервер), мы лишь подменяем адреса и пересчитываем контрольные суммы.
  Исходный адрес назначения D:dp хранится в таблице по порту sport, поэтому
  движок знает, куда на самом деле подключаться (и видит SNI в ClientHello).
  Ответные пакеты сервера (TUN_ADDR:lport -> PEER_ADDR:sport) переписываются
  обратно в D:dp -> TUN_ADDR:sport.
* DNS (UDP/53). Отвечаем сами через DoH/UDP-DNS движка. AAAA и прочие типы
  получают пустой ответ - приложения идут по IPv4.
* QUIC (UDP/443) отбиваем ICMP "port unreachable" - приложения сразу
  переходят на TCP, где работает обход.
* Остальной UDP пробрасывается через защищённые сокеты.
"""

import asyncio
import os
import socket
import struct
import time

TUN_ADDR = "10.111.222.1"
PEER_ADDR = "10.111.222.2"

_A = socket.inet_aton(TUN_ADDR)
_P = socket.inet_aton(PEER_ADDR)

FIN, SYN, RST, ACK = 0x01, 0x02, 0x04, 0x10

MAX_FLOWS = 8192
MAX_UDP_FLOWS = 256
UDP_IDLE_SECONDS = 60


# ---------------------------------------------------------------------
# Контрольные суммы
# ---------------------------------------------------------------------


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"

    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def _words(data: bytes):
    return struct.unpack("!%dH" % (len(data) // 2), data)


def csum_update(csum: int, old_words, new_words) -> int:
    """Инкрементальное обновление контрольной суммы (RFC 1624, ур. 3)."""
    total = (~csum) & 0xFFFF

    for old, new in zip(old_words, new_words):
        total += ((~old) & 0xFFFF) + new

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


# ---------------------------------------------------------------------
# Сборка пакетов
# ---------------------------------------------------------------------


def _ip_header(src: bytes, dst: bytes, proto: int, payload_len: int) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + payload_len, 0, 0x4000, 64, proto, 0, src, dst,
    )
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:]


def build_udp(src: bytes, sport: int, dst: bytes, dport: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    # Контрольная сумма UDP = 0 допустима для IPv4 ("не используется").
    return _ip_header(src, dst, 17, len(udp)) + udp


def build_icmp_port_unreachable(orig: bytes) -> bytes:
    """ICMP type 3 code 3 в ответ на исходный пакет (от D к приложению)."""
    ihl = (orig[0] & 15) * 4
    inner = bytes(orig[: ihl + 8])
    body = struct.pack("!BBHI", 3, 3, 0, 0) + inner
    body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
    return _ip_header(bytes(orig[16:20]), bytes(orig[12:16]), 1, len(body)) + body


# ---------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------


def parse_dns_query(data: bytes):
    """-> (name, qtype, question_end) или None, если это не простой запрос."""
    if len(data) < 17:
        return None

    _, flags, qd = struct.unpack("!HHH", data[:6])

    if flags & 0x8000 or qd != 1:
        return None

    pos, labels = 12, []

    while True:
        if pos >= len(data):
            return None

        length = data[pos]

        if length == 0:
            pos += 1
            break

        if length & 0xC0 or pos + 1 + length > len(data):
            return None

        labels.append(data[pos + 1 : pos + 1 + length].decode("ascii", "ignore"))
        pos += 1 + length

    if pos + 4 > len(data):
        return None

    qtype = struct.unpack("!H", data[pos : pos + 2])[0]
    return ".".join(labels), qtype, pos + 4


def build_dns_response(query: bytes, qend: int, ips, rcode: int = 0) -> bytes:
    """Ответ на запрос: пустой (NODATA), с A-записями или с кодом ошибки."""
    answers = b"".join(
        b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
        for ip in (ips or [])
    )
    flags = 0x8180 | (rcode & 0xF)
    header = query[:2] + struct.pack("!HHHHH", flags, 1, len(ips or []), 0, 0)
    return header + query[12:qend] + answers


# ---------------------------------------------------------------------
# Перезапись пакетов (чистая логика, без ввода-вывода)
# ---------------------------------------------------------------------


class TunRouter:
    def __init__(self, listen_port: int):
        self.lport = listen_port
        self.flows = {}  # sport -> [dst_ip(bytes), dport, last_seen]

    def _rewrite(self, pkt: bytearray, ihl: int, src, sport, dst, dport):
        old_addrs = bytes(pkt[12:20])
        old_ports = bytes(pkt[ihl : ihl + 4])
        new_addrs = src + dst
        new_ports = struct.pack("!HH", sport, dport)

        ip_sum = struct.unpack("!H", pkt[10:12])[0]
        ip_sum = csum_update(ip_sum, _words(old_addrs), _words(new_addrs))

        tcp_sum = struct.unpack("!H", pkt[ihl + 16 : ihl + 18])[0]
        tcp_sum = csum_update(
            tcp_sum,
            _words(old_addrs) + _words(old_ports),
            _words(new_addrs) + _words(new_ports),
        )

        pkt[10:12] = struct.pack("!H", ip_sum)
        pkt[12:20] = new_addrs
        pkt[ihl : ihl + 4] = new_ports
        pkt[ihl + 16 : ihl + 18] = struct.pack("!H", tcp_sum)

    def _purge(self):
        if len(self.flows) <= MAX_FLOWS:
            return

        for sport, _ in sorted(self.flows.items(), key=lambda kv: kv[1][2])[
            : len(self.flows) - MAX_FLOWS // 2
        ]:
            del self.flows[sport]

    def translate(self, pkt: bytearray):
        """Разбор одного пакета из TUN.

        Возвращает:
          ("out", пакет)                       - записать в TUN
          ("dns", (sport, server_ip, payload)) - DNS-запрос приложения
          ("quic", пакет)                      - отбить ICMP-ом
          ("udp", (sport, dst_ip, dport, payload))
          None                                 - отбросить
        """
        if len(pkt) < 20 or pkt[0] >> 4 != 4:
            return None

        ihl = (pkt[0] & 15) * 4
        total = struct.unpack("!H", pkt[2:4])[0]

        if ihl < 20 or total < ihl or len(pkt) < total:
            return None

        if len(pkt) > total:
            del pkt[total:]

        # Фрагменты IP не собираем (при MTU туннеля они не встречаются).
        if struct.unpack("!H", pkt[6:8])[0] & 0x3FFF:
            return None

        src, dst, proto = bytes(pkt[12:16]), bytes(pkt[16:20]), pkt[9]

        if src != _A:
            return None

        if proto == 6:
            return self._tcp(pkt, ihl, dst)

        if proto == 17 and len(pkt) >= ihl + 8:
            sport, dport, ulen = struct.unpack("!HHH", pkt[ihl : ihl + 6])
            payload = bytes(pkt[ihl + 8 : ihl + ulen])

            if dport == 53:
                return "dns", (sport, dst, payload)

            if dport == 443:
                return "quic", bytes(pkt)

            return "udp", (sport, dst, dport, payload)

        return None

    def _tcp(self, pkt: bytearray, ihl: int, dst: bytes):
        if len(pkt) < ihl + 20:
            return None

        sport, dport = struct.unpack("!HH", pkt[ihl : ihl + 4])
        flags = pkt[ihl + 13]
        now = time.time()

        if dst == _P and sport == self.lport:
            # Ответ нашего локального сервера приложению.
            flow = self.flows.get(dport)

            if flow is None:
                return None

            flow[2] = now
            self._rewrite(pkt, ihl, flow[0], flow[1], _A, dport)
            return "out", pkt

        # Пакет приложения -> перенаправляем на локальный сервер.
        if flags & (SYN | ACK) == SYN:
            self.flows[sport] = [dst, dport, now]
            self._purge()

        flow = self.flows.get(sport)

        if flow is None or flow[0] != dst or flow[1] != dport:
            return None

        flow[2] = now
        self._rewrite(pkt, ihl, _P, sport, _A, self.lport)
        return "out", pkt


# ---------------------------------------------------------------------
# Ввод-вывод
# ---------------------------------------------------------------------


class _UdpFlow:
    def __init__(self, transport):
        self.transport = transport
        self.last = time.time()


class TunRelay:
    """Читает TUN, перенаправляет TCP на локальный сервер движка, обслуживает DNS/UDP."""

    def __init__(self, engine, fd: int, listen_sock=None, udp_target=None):
        self.engine = engine
        self.fd = fd
        self.listen_sock = listen_sock
        # Для тестов: подмена адреса, куда уходит UDP.
        self.udp_target = udp_target or (lambda ip, port: (ip, port))
        self.router = None
        self.server = None
        self.udp_flows = {}
        self._tasks = set()
        self._janitor = None
        self._write_errors = 0

    def log(self, msg):
        self.engine.log(msg)

    async def start(self):
        os.set_blocking(self.fd, False)

        if self.listen_sock is not None:
            self.server = await asyncio.start_server(
                self._on_client, sock=self.listen_sock
            )
        else:
            self.server = await asyncio.start_server(
                self._on_client, host=TUN_ADDR, port=0
            )

        lport = self.server.sockets[0].getsockname()[1]
        self.router = TunRouter(lport)

        loop = asyncio.get_running_loop()
        loop.add_reader(self.fd, self._readable)
        self._janitor = loop.create_task(self._clean_udp())

    def stop(self):
        try:
            asyncio.get_running_loop().remove_reader(self.fd)
        except Exception:
            pass

        if self._janitor:
            self._janitor.cancel()

        for task in list(self._tasks):
            task.cancel()

        for flow in list(self.udp_flows.values()):
            try:
                flow.transport.close()
            except Exception:
                pass

        self.udp_flows.clear()

        if self.server:
            self.server.close()

    # --- чтение/запись TUN ---------------------------------------------

    def _readable(self):
        for _ in range(128):
            try:
                data = os.read(self.fd, 65535)
            except BlockingIOError:
                return
            except OSError:
                # Интерфейс закрыт (VPN выключен).
                try:
                    asyncio.get_running_loop().remove_reader(self.fd)
                except Exception:
                    pass
                return

            if not data:
                return

            try:
                self._handle(bytearray(data))
            except Exception as e:  # один плохой пакет не должен валить туннель
                self.log(f"[VPN] ошибка пакета: {type(e).__name__} {e}")

    def write(self, pkt):
        try:
            os.write(self.fd, bytes(pkt))
        except BlockingIOError:
            pass
        except OSError as e:
            self._write_errors += 1

            if self._write_errors == 1:
                self.log(f"[VPN] не удалось записать в туннель: {e}")

    def _spawn(self, coro):
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _handle(self, pkt: bytearray):
        result = self.router.translate(pkt)

        if result is None:
            return

        kind, data = result

        if kind == "out":
            self.write(data)
        elif kind == "dns":
            self._spawn(self._dns(*data))
        elif kind == "quic":
            self.write(build_icmp_port_unreachable(data))
        elif kind == "udp":
            self._spawn(self._udp(*data))

    # --- TCP: подключение приложения к нашему серверу ------------------

    async def _on_client(self, reader, writer):
        peer = writer.get_extra_info("peername") or ("", 0)
        flow = self.router.flows.get(peer[1]) if peer[0] == PEER_ADDR else None

        if flow is None:
            writer.close()
            return

        await self.engine.serve_tunnel(
            reader, writer, socket.inet_ntoa(flow[0]), flow[1]
        )

    # --- DNS -------------------------------------------------------------

    async def _dns(self, sport, server_ip, payload):
        parsed = parse_dns_query(payload)

        if parsed is None:
            return

        name, qtype, qend = parsed

        if qtype == 1:
            ips = await self.engine.resolve_ips(name)

            if ips is None:
                reply = build_dns_response(payload, qend, [], rcode=2)  # SERVFAIL
            else:
                reply = build_dns_response(payload, qend, ips[:8])
        else:
            reply = build_dns_response(payload, qend, [])  # NODATA

        self.write(build_udp(server_ip, 53, _A, sport, reply))

    # --- UDP -------------------------------------------------------------

    async def _udp(self, sport, dst_ip, dport, payload):
        key = (sport, dst_ip, dport)
        flow = self.udp_flows.get(key)

        if flow is None:
            if len(self.udp_flows) >= MAX_UDP_FLOWS:
                return

            relay = self
            loop = asyncio.get_running_loop()

            class Proto(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    f = relay.udp_flows.get(key)

                    if f:
                        f.last = time.time()

                    relay.write(build_udp(dst_ip, dport, _A, sport, data))

            ip, port = self.udp_target(socket.inet_ntoa(dst_ip), dport)
            sock = self.engine.new_socket("udp", ip)

            try:
                sock.connect((ip, port))
                transport, _ = await loop.create_datagram_endpoint(Proto, sock=sock)
            except Exception:
                sock.close()
                return

            flow = self.udp_flows.setdefault(key, _UdpFlow(transport))

        flow.last = time.time()
        flow.transport.sendto(payload)

    async def _clean_udp(self):
        while True:
            await asyncio.sleep(15)
            limit = time.time() - UDP_IDLE_SECONDS

            for key, flow in list(self.udp_flows.items()):
                if flow.last < limit:
                    del self.udp_flows[key]
                    flow.transport.close()
