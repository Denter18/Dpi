import asyncio
import ipaddress
import json
import os
import random
import socket
import ssl
import struct
import threading
import time

from kivy.app import App
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner
from kivy.uix.switch import Switch
from kivy.uix.textinput import TextInput
from kivy.utils import platform


# Настройка цвета фона окна
Window.clearcolor = (0.12, 0.12, 0.14, 1)

# Сколько ждать ClientHello от клиента после "200 Connection Established" (сек)
HELLO_TIMEOUT = 5.0
# Сколько ждать первый ответ сервера в режиме автоопределения (сек).
# Если за это время пришёл RST/EOF/тишина - считаем, что домен блокируется DPI.
AUTODETECT_TIMEOUT = 4.0

# Разрешение имён. Провайдеры подменяют/блокируют DNS-ответы для заблокированных
# доменов (YouTube и др.), поэтому имена разрешаем сами, по порядку:
#   1) DNS-over-HTTPS по IP-адресу БЕЗ SNI (DPI часто режет SNI cloudflare-dns.com
#      и dns.google; сертификат проверяется по IP). Все серверы - параллельно.
#   2) Обычный DNS по UDP на публичные серверы (в т.ч. Яндекс).
#   3) Системный DNS.
# Формат DoH: (ip, Host, путь, порт, имя для проверки сертификата).
DOH_PROVIDERS = [
    ("1.1.1.1", "cloudflare-dns.com", "/dns-query", 443, "1.1.1.1"),
    ("1.0.0.1", "cloudflare-dns.com", "/dns-query", 443, "1.0.0.1"),
    ("8.8.8.8", "dns.google", "/resolve", 443, "8.8.8.8"),
    ("8.8.4.4", "dns.google", "/resolve", 443, "8.8.4.4"),
]
UDP_DNS_SERVERS = [
    ("77.88.8.8", 53),
    ("8.8.8.8", 53),
    ("1.1.1.1", 53),
    ("9.9.9.9", 53),
]
DOH_TIMEOUT = 3.5
UDP_TIMEOUT = 2.5
# Если способ целиком не ответил, не пробуем его столько секунд.
STAGE_DEAD_SECONDS = 120


# =====================================================================
# ЯДРО NODPI v2.3 (Асинхронный прокси с поддержкой Kyber и Disorder)
# =====================================================================


class NoDPIEngine:
    def __init__(
        self,
        host="127.0.0.1",
        port=8881,
        no_disorder=False,
        mode="all",
        domains=None,
        log_cb=None,
        stopped_cb=None,
        use_doh=True,
    ):
        self.host = host
        self.port = int(port)
        self.no_disorder = no_disorder
        self.mode = mode  # 'all', 'blacklist', 'autodetect'
        self.blacklist = set(
            d.strip().lower() for d in (domains or []) if d.strip()
        )
        self.autodetected = set()
        self.use_doh = use_doh
        self.doh_providers = list(DOH_PROVIDERS)
        self.udp_servers = list(UDP_DNS_SERVERS)
        self._stage_dead = {}  # способ -> до какого времени не пробовать
        self._stage_ok_logged = set()
        self._dns_cache = {}  # host -> (expires_at, [ip, ...])
        self._dns_logged = set()
        self._ssl_ctx = None
        self.log_cb = log_cb or (lambda msg: None)
        # Вызывается (из потока прокси), если сервер остановился сам - например,
        # из-за занятого порта. Нужен, чтобы интерфейс сбросил кнопку.
        self.stopped_cb = stopped_cb
        self.server = None
        self.loop = None
        self._main_task = None
        self.running = False

    def log(self, msg):
        self.log_cb(msg)

    def is_target_domain(self, domain: str) -> bool:
        if not domain:
            return False

        domain = domain.lower()

        if self.mode == "all":
            return True

        target_set = (
            self.blacklist if self.mode == "blacklist" else self.autodetected
        )

        for d in target_set:
            if domain == d or domain.endswith("." + d):
                return True

        return False

    @staticmethod
    def extract_sni(data: bytes):
        """Извлекает SNI и его точное смещение в пакете TLS ClientHello."""
        try:
            if len(data) < 43 or data[0] != 0x16 or data[5] != 0x01:
                return None, -1

            offset = 43

            # Session ID
            if len(data) < offset + 1:
                return None, -1

            sid_len = data[offset]
            offset += 1 + sid_len

            # Cipher Suites
            if len(data) < offset + 2:
                return None, -1

            cs_len = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2 + cs_len

            # Compression Methods
            if len(data) < offset + 1:
                return None, -1

            comp_len = data[offset]
            offset += 1 + comp_len

            # Extensions
            if len(data) < offset + 2:
                return None, -1

            ext_total_len = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2
            end_ext = min(len(data), offset + ext_total_len)

            while offset + 4 <= end_ext:
                ext_type, ext_len = struct.unpack(
                    "!HH", data[offset : offset + 4]
                )
                offset += 4

                if ext_type == 0x0000:  # server_name extension
                    if offset + 5 <= end_ext:
                        name_type = data[offset + 2]

                        if name_type == 0:
                            name_len = struct.unpack(
                                "!H", data[offset + 3 : offset + 5]
                            )[0]

                            sni_pos = offset + 5

                            if sni_pos + name_len <= end_ext:
                                sni = data[sni_pos : sni_pos + name_len].decode(
                                    "latin1", errors="ignore"
                                )

                                return sni, sni_pos

                offset += ext_len

        except Exception:
            pass

        return None, -1

    @staticmethod
    async def read_full_client_hello(
        reader: asyncio.StreamReader,
    ) -> bytes:
        """Фича v2.3: Полное чтение TLS-записи ClientHello (для поддержки больших Kyber-пакетов).

        Возвращает всё, что клиент прислал первым. Если клиент ничего не
        прислал за HELLO_TIMEOUT (протоколы, где первым говорит сервер),
        возвращает b"" - тогда соединение просто проксируется как есть.
        """
        try:
            # readexactly, а не read(5): read может вернуть меньше 5 байт.
            header = await asyncio.wait_for(
                reader.readexactly(5), timeout=HELLO_TIMEOUT
            )
        except asyncio.IncompleteReadError as e:
            return e.partial
        except asyncio.TimeoutError:
            return b""

        if header[0] != 0x16:
            return header

        record_len = struct.unpack("!H", header[3:5])[0]

        # Запись TLS не бывает длиннее 16 КБ (+ запас на расширения).
        if record_len == 0 or record_len > 16384 + 2048:
            return header

        try:
            body = await asyncio.wait_for(
                reader.readexactly(record_len), timeout=HELLO_TIMEOUT
            )
        except asyncio.IncompleteReadError as e:
            body = e.partial
        except asyncio.TimeoutError:
            body = b""

        return header + body

    # ---------------------------------------------------------------
    # DNS-over-HTTPS
    # ---------------------------------------------------------------

    def _ssl_context(self):
        if self._ssl_ctx is None:
            cafile = None
            try:
                # На Android в системном хранилище нет путей OpenSSL, берём certifi.
                import certifi

                cafile = certifi.where()
            except Exception:
                pass
            self._ssl_ctx = ssl.create_default_context(cafile=cafile)
        return self._ssl_ctx

    @staticmethod
    def _dechunk(body: bytes) -> bytes:
        out = bytearray()
        while body:
            size_line, _, rest = body.partition(b"\r\n")
            try:
                size = int(size_line.split(b";")[0].strip() or b"0", 16)
            except ValueError:
                break
            if size == 0:
                break
            out.extend(rest[:size])
            body = rest[size + 2 :]
        return bytes(out)

    async def _doh_query(self, provider, name: str):
        """Один DoH-запрос (JSON API). Возвращает ([ip, ...], ttl)."""
        ip, host_header, path, port, tls_name = provider

        reader, writer = await asyncio.open_connection(
            ip, port, ssl=self._ssl_context(), server_hostname=tls_name
        )

        try:
            request = (
                f"GET {path}?name={name}&type=A HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                "Accept: application/dns-json\r\n"
                "Connection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii"))
            await writer.drain()
            raw = await reader.read()
        finally:
            try:
                writer.close()
            except Exception:
                pass

        head, _, body = raw.partition(b"\r\n\r\n")

        if b" 200" not in head.split(b"\r\n", 1)[0]:
            raise OSError("DoH HTTP: " + head[:40].decode("latin1"))

        if b"transfer-encoding: chunked" in head.lower():
            body = self._dechunk(body)

        data = json.loads(body.decode("utf-8"))
        ips, ttl = [], 300

        for ans in data.get("Answer", []):
            if ans.get("type") == 1:
                ips.append(ans["data"])
                ttl = min(ttl, int(ans.get("TTL", 300)))

        return ips, max(ttl, 60)

    # --- обычный DNS по UDP -------------------------------------------

    @staticmethod
    def _dns_build(name: str):
        tid = random.randint(0, 65535)
        labels = name.rstrip(".").encode("idna").split(b".")
        qname = b"".join(bytes([len(x)]) + x for x in labels) + b"\x00"
        packet = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        return tid, packet + qname + struct.pack("!HH", 1, 1)

    @staticmethod
    def _dns_parse(data: bytes, tid: int):
        """Разбор ответа на A-запрос. ValueError - чужой/битый пакет."""
        if len(data) < 12:
            raise ValueError("short")

        rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])

        if rid != tid or not flags & 0x8000:
            raise ValueError("not our response")

        if flags & 0xF:  # NXDOMAIN, SERVFAIL...: ответ есть, адресов нет
            return [], 300

        def skip_name(pos):
            while True:
                length = data[pos]
                if length == 0:
                    return pos + 1
                if length & 0xC0 == 0xC0:
                    return pos + 2
                pos += 1 + length

        try:
            pos = 12
            for _ in range(qd):
                pos = skip_name(pos) + 4

            ips, ttl = [], 300

            for _ in range(an):
                pos = skip_name(pos)
                rtype, rclass, rttl, rdlen = struct.unpack(
                    "!HHIH", data[pos : pos + 10]
                )
                pos += 10

                if rtype == 1 and rclass == 1 and rdlen == 4:
                    ips.append(socket.inet_ntoa(data[pos : pos + 4]))
                    ttl = min(ttl, rttl)

                pos += rdlen
        except (IndexError, struct.error):
            raise ValueError("malformed")

        return ips, max(ttl, 60)

    async def _udp_query(self, server, name: str):
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        tid, packet = self._dns_build(name)
        parse = self._dns_parse

        class Proto(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport
                transport.sendto(packet)
                # UDP теряется - повторяем один раз через секунду.
                self.retry = loop.call_later(1.0, lambda: transport.sendto(packet))

            def datagram_received(self, data, addr):
                if fut.done():
                    return
                try:
                    fut.set_result(parse(data, tid))
                except ValueError:
                    pass  # чужой пакет - ждём дальше

            def error_received(self, exc):
                if not fut.done():
                    fut.set_exception(exc)

        transport, proto = await loop.create_datagram_endpoint(
            Proto, remote_addr=server
        )

        try:
            return await fut
        finally:
            proto.retry.cancel()
            transport.close()

    # --- выбор способа -----------------------------------------------

    @staticmethod
    async def _first_answer(coros, timeout: float):
        """Параллельно запускает запросы, возвращает первый непустой ответ.

        Возвращает (ips, ttl, answered, last_error): answered=True, если хоть
        один сервер ответил (пусть и пустым ответом), т.е. способ рабочий.
        """
        tasks = [asyncio.ensure_future(c) for c in coros]
        pending = set(tasks)
        deadline = time.time() + timeout
        answered, last_err = False, None

        try:
            while pending:
                left = deadline - time.time()
                if left <= 0:
                    break

                done, pending = await asyncio.wait(
                    pending, timeout=left, return_when=asyncio.FIRST_COMPLETED
                )

                if not done:
                    break

                for task in done:
                    if task.exception() is not None:
                        last_err = task.exception()
                        continue

                    answered = True
                    ips, ttl = task.result()

                    if ips:
                        return ips, ttl, True, None
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()

            await asyncio.gather(*tasks, return_exceptions=True)

        return [], 300, answered, last_err

    async def resolve(self, host: str):
        """Список IPv4-адресов для подключения."""
        try:
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass

        if not self.use_doh:
            return [host]

        key = host.lower()
        cached = self._dns_cache.get(key)

        if cached and cached[0] > time.time():
            return cached[1]

        stages = (
            ("DoH", DOH_TIMEOUT, lambda: [self._doh_query(p, key) for p in self.doh_providers]),
            ("UDP DNS", UDP_TIMEOUT, lambda: [self._udp_query(s, key) for s in self.udp_servers]),
        )

        for label, timeout, make in stages:
            if self._stage_dead.get(label, 0) > time.time():
                continue

            ips, ttl, answered, err = await self._first_answer(make(), timeout)

            if ips:
                self._dns_cache[key] = (time.time() + ttl, ips)

                if label not in self._stage_ok_logged:
                    self._stage_ok_logged.add(label)
                    self.log(f"[DNS] {label} работает")

                await self._log_dns_mismatch(key, ips)
                return ips

            if not answered:
                self._stage_dead[label] = time.time() + STAGE_DEAD_SECONDS
                self.log(
                    f"[DNS] {label} недоступен "
                    f"({type(err).__name__ if err else 'таймаут'}), "
                    f"пауза {STAGE_DEAD_SECONDS} с"
                )

        return [host]

    async def _log_dns_mismatch(self, host: str, found_ips):
        """Один раз на домен показываем, если системный DNS отдаёт другое (подмена)."""
        if host in self._dns_logged:
            return
        self._dns_logged.add(host)

        try:
            loop = asyncio.get_running_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, None, family=socket.AF_INET), timeout=3.0
            )
            system_ips = sorted({i[4][0] for i in infos})
        except Exception as e:
            system_ips = [f"ошибка {type(e).__name__}"]

        if not set(system_ips) & set(found_ips):
            self.log(
                f"[DNS] {host}: системный DNS={','.join(system_ips)}, "
                f"используем {','.join(found_ips[:3])}"
            )

    async def open_remote(self, host: str, port: int):
        ips = await self.resolve(host)
        last_err = None

        for ip in ips[:4]:
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=8.0
                )
            except Exception as e:
                last_err = e

        raise last_err or OSError("не удалось подключиться")

    async def connect_with_autodetect(
        self,
        host: str,
        port: int,
        domain: str,
        ch_data: bytes,
        sni_pos: int,
        sni_len: int,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        client_writer: asyncio.StreamWriter,
    ):
        """Режим автоопределения.

        Сначала отправляем ClientHello как есть. Если в ответ сервер не
        прислал ни байта (DPI сбросил соединение или молча отбросил пакеты),
        запоминаем домен и тут же повторяем подключение с фрагментацией -
        браузеру ничего перезапрашивать не нужно.

        Возвращает актуальную пару (reader, writer) для дальнейшего проксирования.
        """
        first = b""

        try:
            remote_writer.write(ch_data)
            await remote_writer.drain()

            first = await asyncio.wait_for(
                remote_reader.read(16384), timeout=AUTODETECT_TIMEOUT
            )
        except (asyncio.TimeoutError, OSError):
            first = b""

        if first:
            client_writer.write(first)
            await client_writer.drain()
            return remote_reader, remote_writer

        self.autodetected.add(domain.lower())
        self.log(f"[Auto] Блокировка обнаружена: {domain}, повтор с обходом DPI")

        try:
            remote_writer.close()
        except Exception:
            pass

        new_reader, new_writer = await self.open_remote(host, port)
        await self.send_fragmented_tls(new_writer, ch_data, sni_pos, sni_len)

        return new_reader, new_writer

    async def send_fragmented_tls(
        self,
        writer: asyncio.StreamWriter,
        data: bytes,
        sni_pos: int,
        sni_len: int,
    ):
        """Фича v2.3: Фрагментация ClientHello с режимом disorder (или без него при --no-disorder)."""
        sock = writer.get_extra_info("socket")

        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass

        if sni_pos <= 0:
            writer.write(data)
            await writer.drain()
            return

        mid = sni_pos + max(1, sni_len // 2)

        if self.no_disorder:
            # Базовая фрагментация ровно посередине SNI (--no-disorder)
            parts = [data[:mid], data[mid:]]

            for part in parts:
                writer.write(part)
                await writer.drain()
                await asyncio.sleep(0.002)
        else:
            # Режим Disorder (по умолчанию в v2.3): нарезка заголовка, SNI по кускам и отправка с принудительным сбросом буфера.
            parts = []

            if sni_pos > 5:
                parts.append(data[:5])
                parts.append(data[5:sni_pos])
            else:
                parts.append(data[:sni_pos])

            # Дробим сам SNI на мелкие фрагменты по 1-3 байта
            idx = sni_pos
            sni_end = sni_pos + sni_len

            while idx < sni_end:
                step = random.randint(1, 3)
                parts.append(data[idx : min(idx + step, sni_end)])
                idx += step

            parts.append(data[sni_end:])

            for part in parts:
                if part:
                    writer.write(part)
                    await writer.drain()
                    await asyncio.sleep(0.005)

    async def pipe(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        try:
            while self.running:
                data = await reader.read(16384)

                if not data:
                    break

                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ):
        remote_writer = None
        try:
            first_line = await asyncio.wait_for(
                client_reader.readline(), timeout=10.0
            )

            if not first_line:
                client_writer.close()
                return

            line_str = first_line.decode("latin1", errors="ignore").strip()
            parts = line_str.split(" ")

            if len(parts) < 2:
                client_writer.close()
                return

            method = parts[0].upper()
            target = parts[1]

            # Вычитываем остальные заголовки HTTP-прокси
            headers = bytearray()
            while True:
                h_line = await asyncio.wait_for(
                    client_reader.readline(), timeout=10.0
                )

                if not h_line or h_line in (b"\r\n", b"\n"):
                    break

                headers.extend(h_line)

            if method == "CONNECT":
                if ":" in target:
                    host, port_str = target.rsplit(":", 1)
                    port = int(port_str)
                else:
                    host, port = target, 443

                # IPv6-адрес приходит в скобках: [2001:db8::1]:443
                host = host.strip("[]")

                try:
                    remote_reader, remote_writer = await self.open_remote(
                        host, port
                    )
                except Exception as e:
                    self.log(
                        f"[Ошибка] не подключиться к {host}:{port} - "
                        f"{type(e).__name__} {e}"
                    )

                    if self.mode == "autodetect":
                        self.autodetected.add(host.lower())

                    # Браузер увидит понятную ошибку шлюза, а не пустой ответ.
                    try:
                        client_writer.write(
                            b"HTTP/1.1 502 Bad Gateway\r\n"
                            b"Content-Length: 0\r\n\r\n"
                        )
                        await client_writer.drain()
                    except Exception:
                        pass

                    client_writer.close()
                    return

                client_writer.write(
                    b"HTTP/1.1 200 Connection Established\r\n\r\n"
                )
                await client_writer.drain()

                # Читаем полностью ClientHello (v2.3)
                try:
                    ch_data = await self.read_full_client_hello(client_reader)
                except Exception:
                    client_writer.close()
                    remote_writer.close()
                    return

                if ch_data:
                    sni, sni_pos = self.extract_sni(ch_data)
                    check_domain = sni or host
                    is_tls = sni_pos > 0

                    if is_tls and self.is_target_domain(check_domain):
                        self.log(f"[DPI Bypass] {check_domain}")

                        await self.send_fragmented_tls(
                            remote_writer, ch_data, sni_pos, len(sni)
                        )
                    elif is_tls and self.mode == "autodetect":
                        # Домен ещё не известен как заблокированный: пробуем
                        # без обхода, при сбое сами повторяем с обходом.
                        (
                            remote_reader,
                            remote_writer,
                        ) = await self.connect_with_autodetect(
                            host,
                            port,
                            check_domain,
                            ch_data,
                            sni_pos,
                            len(sni),
                            remote_reader,
                            remote_writer,
                            client_writer,
                        )
                    else:
                        remote_writer.write(ch_data)
                        await remote_writer.drain()

                await asyncio.gather(
                    self.pipe(client_reader, remote_writer),
                    self.pipe(remote_reader, client_writer),
                )
            else:
                # Обычный HTTP-запрос
                host = ""
                port = 80

                for h in headers.decode("latin1", errors="ignore").split(
                    "\r\n"
                ):
                    if h.lower().startswith("host:"):
                        host_val = h.split(":", 1)[1].strip()

                        if ":" in host_val:
                            host, p = host_val.rsplit(":", 1)
                            port = int(p)
                        else:
                            host = host_val

                        break

                if not host:
                    client_writer.close()
                    return

                remote_reader, remote_writer = await self.open_remote(
                    host, port
                )

                remote_writer.write(first_line + bytes(headers) + b"\r\n")
                await remote_writer.drain()

                await asyncio.gather(
                    self.pipe(client_reader, remote_writer),
                    self.pipe(remote_reader, client_writer),
                )

        except Exception:
            pass
        finally:
            try:
                client_writer.close()
            except Exception:
                pass

            if remote_writer:
                try:
                    remote_writer.close()
                except Exception:
                    pass

    async def _run_server(self):
        self.server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )

        self.log(f"Прокси запущен на {self.host}:{self.port}")

        mode_label = (
            "Disorder (v2.3)" if not self.no_disorder else "Standard (--no-disorder)"
        )
        self.log(f"Метод: {mode_label} | Режим: {self.mode}")

        # Без "async with": при выходе он вызывает wait_closed(), который
        # (Python 3.12+) ждёт закрытия ВСЕХ активных соединений и подвисает.
        try:
            await self.server.serve_forever()
        finally:
            self.server.close()

    def start_in_thread(self):
        self.running = True

        def target():
            loop = asyncio.new_event_loop()
            self.loop = loop
            asyncio.set_event_loop(loop)

            try:
                self._main_task = loop.create_task(self._run_server())

                # stop() мог быть вызван, пока поток ещё стартовал.
                if not self.running:
                    self._main_task.cancel()

                loop.run_until_complete(self._main_task)
            except asyncio.CancelledError:
                pass  # штатная остановка через stop()
            except Exception as e:
                if self.running:
                    self.log(f"Ошибка: {e}")
            finally:
                # Закрываем все ещё открытые соединения, чтобы не оставлять
                # висящие задачи ("Task was destroyed but it is pending").
                try:
                    pending = asyncio.all_tasks(loop)
                    for task in pending:
                        task.cancel()
                    if pending:
                        loop.run_until_complete(
                            asyncio.gather(*pending, return_exceptions=True)
                        )

                    # Даём транспортам обработать connection_lost до закрытия цикла.
                    loop.run_until_complete(asyncio.sleep(0.05))
                except Exception:
                    pass

                loop.close()

                # Сервер остановился сам (например, порт занят) - сообщаем UI.
                died_on_its_own = self.running
                self.running = False

                if died_on_its_own and self.stopped_cb:
                    try:
                        self.stopped_cb()
                    except Exception:
                        pass

        t = threading.Thread(target=target, daemon=True)
        t.start()

    def stop(self):
        was_running = self.running
        self.running = False

        loop, task = self.loop, self._main_task

        if loop and task and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:
                pass  # цикл уже закрыт

        if was_running:
            self.log("Прокси остановлен.")


# =====================================================================
# ГРАФИЧЕСКИЙ ИНТЕРФЕЙС ANDROID (Kivy)
# =====================================================================


class AndroidVpn:
    """Запуск/остановка Java-сервиса NoDpiVpnService (см. java_src/).

    Сервис ничего не маршрутизирует, а только выставляет системный HTTP-прокси
    на локальный адрес NoDPI - это нужно для работы в мобильной сети (LTE),
    где прокси нельзя задать в настройках Wi-Fi.

    Все обращения к Android API импортируются лениво и обёрнуты в try/except:
    на ПК (и при любой ошибке) приложение продолжает работать как обычный прокси.
    """

    REQUEST_CODE = 0x4E44
    RESULT_OK = -1  # android.app.Activity.RESULT_OK
    SERVICE_CLASS = "org.gvcoder.nodpi.NoDpiVpnService"

    def __init__(self, log_cb):
        self.log = log_cb
        self._pending = None

    @staticmethod
    def available():
        return platform == "android"

    def start(self, host, port):
        if not self.available():
            return

        try:
            from android import activity
            from jnius import autoclass

            activity_cls = autoclass("org.kivy.android.PythonActivity")
            vpn_service = autoclass("android.net.VpnService")
            current = activity_cls.mActivity

            self._pending = (host, port)

            # Если разрешение на VPN ещё не выдано - система покажет диалог.
            prepare_intent = vpn_service.prepare(current)

            if prepare_intent is None:
                self._launch(host, port)
            else:
                activity.bind(on_activity_result=self._on_activity_result)
                current.startActivityForResult(
                    prepare_intent, self.REQUEST_CODE
                )
        except Exception as e:
            self.log(f"VPN: не удалось запустить ({e})")

    def stop(self):
        if not self.available():
            return

        self._pending = None

        try:
            from jnius import autoclass

            activity_cls = autoclass("org.kivy.android.PythonActivity")
            intent_cls = autoclass("android.content.Intent")
            current = activity_cls.mActivity

            intent = intent_cls()
            intent.setClassName(current.getPackageName(), self.SERVICE_CLASS)
            intent.setAction("STOP")
            current.startService(intent)
        except Exception as e:
            self.log(f"VPN: не удалось остановить ({e})")

    def _on_activity_result(self, request_code, result_code, intent):
        if request_code != self.REQUEST_CODE:
            return

        try:
            from android import activity

            activity.unbind(on_activity_result=self._on_activity_result)
        except Exception:
            pass

        pending, self._pending = self._pending, None

        if result_code == self.RESULT_OK and pending:
            self._launch(*pending)
        else:
            self.log("VPN: разрешение не выдано, системный прокси не включён")

    def _launch(self, host, port):
        try:
            from jnius import autoclass

            activity_cls = autoclass("org.kivy.android.PythonActivity")
            intent_cls = autoclass("android.content.Intent")
            current = activity_cls.mActivity

            intent = intent_cls()
            intent.setClassName(current.getPackageName(), self.SERVICE_CLASS)
            # Строки, а не int: не зависим от выбора перегрузки putExtra.
            intent.putExtra("HOST", str(host))
            intent.putExtra("PORT", str(port))
            current.startService(intent)

            self.log(f"VPN: системный прокси {host}:{port} включён")
        except Exception as e:
            self.log(f"VPN: не удалось запустить сервис ({e})")


class NoDPIApp(App):
    def build(self):
        self.engine = None
        self.vpn = AndroidVpn(self.append_log)
        self.vpn_active = False
        root = BoxLayout(
            orientation="vertical", padding=dp(16), spacing=dp(10)
        )

        # Заголовок
        title = Label(
            text="NoDPI v2.3 (Android)",
            font_size=dp(22),
            bold=True,
            size_hint_y=None,
            height=dp(36),
            color=(0.3, 0.8, 1, 1),
        )
        root.add_widget(title)

        # Хост и Порт
        hp_box = BoxLayout(size_hint_y=None, height=dp(40), spacing=dp(10))
        hp_box.add_widget(Label(text="Адрес:", size_hint_x=0.25))

        self.host_input = TextInput(
            text="127.0.0.1", multiline=False, size_hint_x=0.45
        )
        hp_box.add_widget(self.host_input)

        self.port_input = TextInput(
            text="8881", multiline=False, size_hint_x=0.3
        )
        hp_box.add_widget(self.port_input)

        root.add_widget(hp_box)

        # Переключатель --no-disorder
        dis_box = BoxLayout(size_hint_y=None, height=dp(40))
        dis_box.add_widget(
            Label(text="Отключить Disorder (--no-disorder):", size_hint_x=0.75)
        )

        self.no_disorder_switch = Switch(active=False, size_hint_x=0.25)
        dis_box.add_widget(self.no_disorder_switch)

        root.add_widget(dis_box)

        # DNS через DoH (обход подмены DNS провайдером)
        doh_box = BoxLayout(size_hint_y=None, height=dp(40))
        doh_box.add_widget(
            Label(text="Свой DNS (обход подмены):", size_hint_x=0.75)
        )

        self.doh_switch = Switch(active=True, size_hint_x=0.25)
        doh_box.add_widget(self.doh_switch)

        root.add_widget(doh_box)

        # Системный прокси через VPN-сервис (для LTE). Только на Android.
        vpn_box = BoxLayout(size_hint_y=None, height=dp(40))
        vpn_box.add_widget(
            Label(text="Системный прокси через VPN (LTE):", size_hint_x=0.75)
        )

        self.vpn_switch = Switch(
            active=False,
            size_hint_x=0.25,
            disabled=not AndroidVpn.available(),
        )
        vpn_box.add_widget(self.vpn_switch)

        root.add_widget(vpn_box)

        # Режим фильтрации
        mode_box = BoxLayout(size_hint_y=None, height=dp(42), spacing=dp(10))
        mode_box.add_widget(Label(text="Режим:", size_hint_x=0.35))

        self.mode_spinner = Spinner(
            text="Все сайты (All)",
            values=(
                "Все сайты (All)",
                "Чёрный список (Blacklist)",
                "Автоопределение (Auto)",
            ),
            size_hint_x=0.65,
        )
        mode_box.add_widget(self.mode_spinner)

        root.add_widget(mode_box)

        # Список доменов (Blacklist)
        root.add_widget(
            Label(
                text="Домены для Blacklist (по одному на строку):",
                size_hint_y=None,
                height=dp(24),
            )
        )

        self.domains_input = TextInput(
            text=(
                "youtube.com\n"
                "googlevideo.com\n"
                "ytimg.com\n"
                "ggpht.com\n"
                "youtu.be\n"
                "discord.com\n"
                "discordapp.com"
            ),
            size_hint_y=0.28,
        )
        root.add_widget(self.domains_input)

        # Кнопка Старт / Стоп
        self.btn_toggle = Button(
            text="ЗАПУСТИТЬ ПРОКСИ",
            size_hint_y=None,
            height=dp(52),
            background_normal="",
            background_color=(0.18, 0.65, 0.32, 1),
            bold=True,
            font_size=dp(16),
        )
        self.btn_toggle.bind(on_press=self.toggle_proxy)
        root.add_widget(self.btn_toggle)

        # Лог работы
        self.log_label = Label(
            text="Готов к запуску. Настройте прокси 127.0.0.1:8881 в Wi-Fi или браузере.\n",
            size_hint_y=None,
            halign="left",
            valign="top",
            font_size=dp(12),
        )
        self.log_label.bind(
            width=lambda *x: self.log_label.setter("text_size")(
                self.log_label, (self.log_label.width, None)
            ),
            texture_size=lambda *x: self.log_label.setter("height")(
                self.log_label, self.log_label.texture_size[1]
            ),
        )

        scroll = ScrollView(size_hint_y=0.35)
        scroll.add_widget(self.log_label)
        root.add_widget(scroll)

        return root

    def append_log(self, msg):
        def _update(dt):
            lines = (self.log_label.text + "\n" + msg).split("\n")[-60:]
            self.log_label.text = "\n".join(lines)

        Clock.schedule_once(_update, 0)

    def _set_idle_ui(self):
        self.btn_toggle.text = "ЗАПУСТИТЬ ПРОКСИ"
        self.btn_toggle.background_color = (0.18, 0.65, 0.32, 1)

    def _set_running_ui(self):
        self.btn_toggle.text = "ОСТАНОВИТЬ ПРОКСИ"
        self.btn_toggle.background_color = (0.8, 0.22, 0.22, 1)

    def _read_port(self):
        raw = self.port_input.text.strip() or "8881"

        try:
            port = int(raw)
        except ValueError:
            port = 0

        if not 1 <= port <= 65535:
            self.append_log("Ошибка: порт должен быть числом от 1 до 65535")
            return None

        return port

    def _on_engine_stopped(self):
        """Прокси остановился сам (например, порт занят). Вызывается из потока."""

        def _reset(dt):
            if self.vpn_active:
                self.vpn.stop()
                self.vpn_active = False

            self.engine = None
            self._set_idle_ui()

        Clock.schedule_once(_reset, 0)

    def stop_proxy(self):
        if self.vpn_active:
            self.vpn.stop()
            self.vpn_active = False

        if self.engine:
            self.engine.stop()
            self.engine = None

        self._set_idle_ui()

    def toggle_proxy(self, instance):
        if self.engine and self.engine.running:
            self.stop_proxy()
            return

        port = self._read_port()

        if port is None:
            return

        mode_map = {
            "Все сайты (All)": "all",
            "Чёрный список (Blacklist)": "blacklist",
            "Автоопределение (Auto)": "autodetect",
        }

        host = self.host_input.text.strip() or "127.0.0.1"
        domains = self.domains_input.text.splitlines()

        self.engine = NoDPIEngine(
            host=host,
            port=port,
            no_disorder=self.no_disorder_switch.active,
            mode=mode_map.get(self.mode_spinner.text, "all"),
            domains=domains,
            log_cb=self.append_log,
            stopped_cb=self._on_engine_stopped,
            use_doh=self.doh_switch.active,
        )

        self.engine.start_in_thread()
        self._set_running_ui()

        if self.vpn_switch.active and AndroidVpn.available():
            # Системный прокси всегда указывает на локальный адрес.
            self.vpn.start("127.0.0.1", port)
            self.vpn_active = True

    def on_pause(self):
        # Разрешаем уходить в фон, а не останавливать приложение (Android).
        return True

    def on_resume(self):
        pass

    def on_stop(self):
        self.stop_proxy()


if __name__ == "__main__":
    NoDPIApp().run()
