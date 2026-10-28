import asyncio

import os

import random

import socket

import struct

import threading

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



# Настройка цвета фона окна

Window.clearcolor = (0.12, 0.12, 0.14, 1)





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

    ):

        self.host = host

        self.port = int(port)

        self.no_disorder = no_disorder

        self.mode = mode  # 'all', 'blacklist', 'autodetect'

        self.blacklist = set(

            d.strip().lower() for d in (domains or []) if d.strip()

        )

        self.autodetected = set()

        self.log_cb = log_cb or (lambda msg: None)

        self.server = None

        self.loop = None

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

        """Фича v2.3: Полное чтение TLS-записи ClientHello (для поддержки больших Kyber-пакетов)."""

        header = await asyncio.wait_for(reader.read(5), timeout=10.0)

        if not header or len(header) < 5 or header[0] != 0x16:

            return header

        record_len = struct.unpack("!H", header[3:5])[0]

        body = bytearray()

        while len(body) < record_len:

            chunk = await asyncio.wait_for(

                reader.read(record_len - len(body)), timeout=10.0

            )

            if not chunk:

                break

            body.extend(chunk)

        return header + bytes(body)



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

            # Режим Disorder (по умолчанию в v2.3): нарезка заголовка, SNI по кускам и отправка с принудительным сбросом буфера

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



                try:

                    remote_reader, remote_writer = await asyncio.wait_for(

                        asyncio.open_connection(host, port), timeout=10.0

                    )

                except Exception:

                    if self.mode == "autodetect":

                        self.autodetected.add(host.lower())

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

                    if sni_pos > 0 and self.is_target_domain(check_domain):

                        self.log(f"[DPI Bypass] {check_domain}")

                        await self.send_fragmented_tls(

                            remote_writer, ch_data, sni_pos, len(sni)

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



                remote_reader, remote_writer = await asyncio.wait_for(

                    asyncio.open_connection(host, port), timeout=10.0

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

            "Disorder (v2.3)"

            if not self.no_disorder

            else "Standard (--no-disorder)"

        )

        self.log(f"Метод: {mode_label} | Режим: {self.mode}")

        async with self.server:

            await self.server.serve_forever()



    def start_in_thread(self):

        self.running = True



        def target():

            self.loop = asyncio.new_event_loop()

            asyncio.set_event_loop(self.loop)

            try:

                self.loop.run_until_complete(self._run_server())

            except Exception as e:

                if self.running:

                    self.log(f"Ошибка: {e}")



        t = threading.Thread(target=target, daemon=True)

        t.start()



    def stop(self):

        self.running = False

        if self.loop and self.server:

            self.loop.call_soon_threadsafe(self.server.close)

            self.loop.call_soon_threadsafe(self.loop.stop)

        self.log("Прокси остановлен.")





# =====================================================================

# ГРАФИЧЕСКИЙ ИНТЕРФЕЙС ANDROID (Kivy)

# =====================================================================

class NoDPIApp(App):



    def build(self):

        self.engine = None

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



    def toggle_proxy(self, instance):

        if self.engine and self.engine.running:

            self.engine.stop()

            self.engine = None

            self.btn_toggle.text = "ЗАПУСТИТЬ ПРОКСИ"

            self.btn_toggle.background_color = (0.18, 0.65, 0.32, 1)

        else:

            mode_map = {

                "Все сайты (All)": "all",

                "Чёрный список (Blacklist)": "blacklist",

                "Автоопределение (Auto)": "autodetect",

            }

            domains = self.domains_input.text.splitlines()

            self.engine = NoDPIEngine(

                host=self.host_input.text.strip(),

                port=int(self.port_input.text.strip() or 8881),

                no_disorder=self.no_disorder_switch.active,

                mode=mode_map.get(self.mode_spinner.text, "all"),

                domains=domains,

                log_cb=self.append_log,

            )

            self.engine.start_in_thread()

            self.btn_toggle.text = "ОСТАНОВИТЬ ПРОКСИ"

            self.btn_toggle.background_color = (0.8, 0.22, 0.22, 1)





if __name__ == "__main__":

    NoDPIApp().run()
