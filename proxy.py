#!/usr/bin/env python3
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
'''
Proxy server/client module
Client schemes: direct, ssh, socks4, socks5
Server schemes: http, http:connect, socks4, socks5
'''
from __future__ import annotations
from abc import abstractmethod
from typing import Any, Callable, Union, Optional, TypeVar, Type
from itertools import chain
import asyncio
import logging
import socket
import re
import ipaddress
import asyncssh
import aiosocks


ProtocolT = TypeVar("ProtocolT", bound=asyncio.BaseProtocol)


class Url:
    '''
    urllib.parse.urlparse replacement for special symbols in password
    [scheme://][username[:password]@][hostname[:port]][/uri][?param1=value&param2=value][#fragment]
    '''
    parser = r'^(?:(?P<scheme>\w+?)://)?(?:(?P<username>[^:\s]+)(?::(?P<password>.*))?@)?(?P<hostid>(?P<hostname>[^\s#@/:]*)?(?::(?P<port>\d+))?)?(?P<uri>(?P<path>/[^#?]*)(?:\?(?P<rawparams>[^#]*)?)?(?:#(?P<fragment>.*)?)?)?$'
    parse = re.compile(parser)
    DEFAULT = {'http': 80, 'https': 443, 'ssh': 22}
    def __init__(self, url: str):
        self.url = str(url)
        self.scheme: Optional[str] = None
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.hostid: str
        self.hostname: str
        self.port: int
        self.uri: Optional[str] = None
        self.path: Optional[str] = None
        self.fragment: Optional[str] = None
        self.rawparams: Optional[str]
        self.params: dict[str,str] = {}

        parse = self.parse.fullmatch(self.url)
        if parse:
            self.__dict__.update(parse.groupdict())
            if self.port:
                self.port = int(self.port)
            elif self.scheme:
                self.port = self.DEFAULT.get(self.scheme.lower(), 0)
            else:
                self.port = 0

            if self.rawparams:
                for param in self.rawparams.split('&'):
                    key, value = param.split('=', 1)
                    self.params[key] = value
        else:
            raise SyntaxError(f'Url parse error for {url}')

    def __repr__(self) -> str:
        return repr(self.__dict__)

    def __str__(self) -> str:
        return self.url


class HttpBody:
    '''
    simple parse http request
    '''
    def __init__(self, data: bytes):
        self.data = data
        request, self.tail = data.split(b'\r\n', 1)
        self.method, path, self.ver = request.split(b' ', 2)
        self.url = Url(path.decode())

    def __bytes__(self) -> bytes:
        return b'%b %b %b\r\n%b' % (self.method, self.url.uri.encode() if self.url.uri else b'/', self.ver, self.tail)

class HostIP(dict[str,list[str]]):
    '''parse hosts helper class'''
    def __init__(self):
        super().__init__()
        self._wcdict: dict[str,list[str]] = {}

    def __iadd__(self, other: str):
        if other:
            ip_address, *host = other.split()

            for i in host:
                if i.startswith('*'):
                    iplist = self._wcdict.setdefault(i[1:], [])
                else:
                    iplist = self.setdefault(i, [])

                if ip_address not in iplist:
                    iplist.append(ip_address)

        return self

    def __call__(self, hosts: Union[list[str], str, None]):
        '''load hosts like multiline string'''
        if hosts:
            hostslist = hosts if isinstance(hosts, list) else hosts.splitlines()
            for host in hostslist:
                if not host.strip().startswith('#'):
                    self += host
        else:
            self.clear()
            self._wcdict.clear()

    def _get(self, key: str) -> Optional[list[str]]:
        value = super().get(key)
        if not value:
            for wckey, wcvalue in self._wcdict.items():
                if key.endswith(wckey):
                    value = wcvalue
        return value

    def get(self, key: str) -> str:
        value = self._get(key)
        if value:
            return value[0]
        return key

    def print(self, key: str) -> str:
        value = self._get(key)
        if value:
            return f'{key}[{value[0]}]'
        return key

    def rotate(self, key: str):
        '''rotate to the next available ip'''
        value = self._get(key)
        if value:
            value.append(value.pop(0))


class MatchElement:
    '''matching element factory'''
    _matchcls: list[Type[MatchElement]] = []
    def __init__(self, element: str) -> None:
        self.element: str = element
    def __init_subclass__(cls):
        MatchElement._matchcls.append(cls)
    def __new__(cls, element: str):
        if cls is not __class__:
            return super().__new__(cls)
        for child in MatchElement._matchcls:
            try:
                return child(element)
            except ValueError:
                pass
        raise ValueError
    def __repr__(self) -> str:
        return repr(self.element)

class IsRegex:
    '''matching element is regex'''
    def __init__(self, regex: str) -> None:
        self._regex = re.compile(regex)
    def __eq__(self, __o: str) -> bool:
        return self._regex.fullmatch(__o) is not None
    def pattern(self) -> str:
        '''return: regex pattern'''
        return self._regex.pattern
    def __str__(self) -> str:
        return f'/{self._regex.pattern}/i.test(host)'

class IsInNet(MatchElement):
    '''input: 10.0.0.0/24'''
    def __init__(self, element: str):
        self.net = ipaddress.ip_network(element)
        MatchElement.__init__(self, element)
    def __eq__(self, __o: Any) -> bool:
        try:
            return ipaddress.ip_address(__o) in self.net
        except ValueError:
            return False
    def __str__(self):
        return f'isInNet(host, "{self.net.network_address}", "{self.net.netmask}")'

class IsInNetRE(IsRegex, MatchElement):
    '''input: 10.0.(1|2).*'''
    def __init__(self, element: str):
        if not re.fullmatch(r'[\d.*|()\[\]{}+]+', element):
            raise ValueError
        MatchElement.__init__(self, element)
        IsRegex.__init__(self, element.replace('.',r'\.').replace('*',r'\d{1,3}'))

class DnsDomainIs(MatchElement):
    '''input: domain.local'''
    def __init__(self, element: str):
        if not re.fullmatch(r'[\w.-]+', element):
            raise ValueError
        MatchElement.__init__(self, element)
    def __eq__(self, __o: str) -> bool:
        return self.element == __o or __o.endswith('.' + self.element)
    def __str__(self):
        return f'dnsDomainIs(host, "{self.element}")'

class DnsDomainIsRE(IsRegex, MatchElement):
    '''input: (my|other)domain.local'''
    def __init__(self, element: str):
        if not re.fullmatch(r'[\w.*\-|()\[\]{}+?]+\.[a-z]{2,}', element):
            raise ValueError
        MatchElement.__init__(self, element)
        IsRegex.__init__(self, r'(?:.+\.)?' + element.replace('.',r'\.').replace('*','.*'))

class MatchList(list):
    '''
    a = MatchList()
    a.append(MatchElement('test'))
    "domain.test" in a
    '''
    def __init__(self):
        super().__init__()
        self.regex = None
    def __eq__(self, __o: str) -> bool:
        return not self or __o in self
    def __str__(self):
        pattern = (str(x) for x in self if not isinstance(x, IsRegex))
        regex = [x.pattern() for x in self if isinstance(x, IsRegex)]
        if regex:
            pattern = chain(pattern, (r'/^(:?' + '|'.join(regex) + r')$/i.test(host)',))
        return  ' || '.join(pattern) if self else 'true'


class BaseClient:
    '''Base client session class'''
    _clientlist: dict[str, Type[BaseClient]] = {}

    def __init__(self, options: Url, proxylist: Optional[list[str]]=None):
        self.options = options
        self.hosts = HostIP()
        self._loop = asyncio.get_event_loop()
        self.jumphost = BaseClient.connection(proxylist) if proxylist else self._loop
        self.matchlist = MatchList()

        proxynames = []
        if isinstance(self.jumphost, BaseClient):
            proxynames.append(self.jumphost.proxyid)
        proxynames.append(f'{options.scheme}:{options.hostid}')
        self.proxyid = ' '.join(proxynames)
        self.log = logging.getLogger(self.proxyid)

    def __repr__(self):
        return f'[{self.proxyid}] rule={repr(self.matchlist)}'

    @classmethod
    def __init_subclass__(cls, /, scheme: str):
        cls._clientlist[scheme] = cls

    @staticmethod
    def connection(proxylist: Union[list[str],str,None]=None) -> BaseClient:
        '''select client connection class by scheme in connection url'''
        if isinstance(proxylist, str) or proxylist.__class__.__name__ == 'YamlEnv':
            proxylist = [str(proxylist)]
        if proxylist:
            options = Url(proxylist.pop())
        else:
            options = Url('direct://')
        if options.scheme in BaseClient._clientlist:
            return BaseClient._clientlist[options.scheme](options, proxylist)
        raise SyntaxError(f"Scheme '{options.scheme}' not available. Possible values: {', '.join(BaseClient._clientlist.keys())}")

    def rule(self, net: list[str]):
        '''install regex rule to check if client session can open connection'''
        self.matchlist.extend(map(MatchElement, net))

    def match_rule(self, host: str) -> bool:
        '''check if client session can open connection to host'''
        return self.matchlist == host

    @abstractmethod
    async def create_connection(self, client_factory: Callable[[], ProtocolT], host: str, port: int) -> tuple[asyncio.Transport, ProtocolT]:
        '''create connection to host using client session'''
        raise NotImplementedError


class DirectClient(BaseClient, scheme='direct'):
    '''open client session using default asyncssh with host resolution ability'''
    def __init__(self, *args):
        super().__init__(*args)
        self.log = logging.getLogger(self.__class__.__name__)

    async def create_connection(self, client_factory, host, port):
        return await self._loop.create_connection(client_factory, self.hosts.get(host), port)


class SSHClient(asyncssh.client.SSHClient, BaseClient, scheme='ssh'):
    '''open SSH client session'''
    #fix openwrt connection for asyncssh 2.10
    host_algs = [x.decode() for x in asyncssh.public_key.get_default_x509_certificate_algs()] + \
        [x.decode() for x in asyncssh.public_key.get_default_public_key_algs() if not x.endswith(b'@ssh.com')] + \
        [x.decode() for x in asyncssh.public_key.get_default_certificate_algs() if not x.startswith(b'rsa-sha2-')]

    def __init__(self, options: Url, proxylist: Optional[list[str]]=None):
        super().__init__(options, proxylist)

        self.sshconn: Optional[asyncio.Future] = None
        self.sshoptions = asyncssh.connection.SSHClientConnectionOptions(
            options=None,
            host=options.hostname,
            port=options.port,
            username=options.username,
            password=options.password,
            keepalive_interval=60,
            known_hosts=None,
            server_host_key_algs=self.host_algs,
            client_factory=lambda: self,
            **options.params,
        )

    def _protocol_factory(self):
        return asyncssh.connection.SSHClientConnection(self._loop, self.sshoptions)

    async def create_connection(self, client_factory: Any, host, port):
        try:
            if self.sshconn is None or self.sshconn.cancelled():
                self.sshconn = self._loop.create_future()
                await self.jumphost.create_connection(self._protocol_factory, self.sshoptions.host, self.sshoptions.port)
            elif not self.sshconn.done():
                await self.sshconn
        except (Exception, asyncio.exceptions.CancelledError) as ex:
            self.log.error('establish ssh connection[%s]: %s', self.sshoptions.host, ex)
            if self.sshconn and not self.sshconn.done():
                self.sshconn.cancel()
            else:
                self.sshconn = None
            raise
        else:
            # run create_connection outside of try...except to store already established connection
            protocol: asyncssh.connection.SSHClientConnection = self.sshconn.result()
            return await protocol.create_connection(client_factory, self.hosts.get(host), port)

    def connection_made(self, conn):
        self.log.debug('connection made')
        if self.sshconn:
            self.sshconn.set_result(conn)

    def connection_lost(self, exc):
        if exc:
            self.log.error('connection lost: %s', exc)
        else:
            self.log.debug('connection lost')
        if self.sshconn and not self.sshconn.done():
            self.sshconn.cancel()
        else:
            self.sshconn = None


class Socks5Client(BaseClient, scheme='socks5'):
    '''open Socks5 client session'''
    def _protocol_factory(self, dst, waiter, client_factory):
        if not self.options.port:
            raise Exception('client port not defined')
        proxy = aiosocks.Socks5Addr(self.options.hostname, self.options.port)
        auth = aiosocks.Socks5Auth(self.options.username, self.options.password) if self.options.username and self.options.password else None
        return aiosocks.Socks5Protocol(proxy=proxy, proxy_auth=auth, waiter=waiter, dst=dst, app_protocol_factory=client_factory)

    async def create_connection(self, client_factory, host, port):
        if not self.options.port:
            raise Exception('client port not defined')
        waiter = self._loop.create_future()
        protocol_factory = self._protocol_factory((self.hosts.get(host), port), waiter, client_factory)
        transport, protocol = await self.jumphost.create_connection(lambda: protocol_factory, self.options.hostname, self.options.port)

        try:
            await waiter
        except:
            transport.close()
            raise
        return protocol.app_transport, protocol.app_protocol


class Socks4Client(Socks5Client, scheme='socks4'):
    '''open Socks4 client session'''
    def _protocol_factory(self, dst, waiter, client_factory):
        if not self.options.port:
            raise Exception('client port not defined')
        proxy = aiosocks.Socks4Addr(self.options.hostname, self.options.port)
        auth = aiosocks.Socks4Auth(self.options.username) if self.options.username else None
        return aiosocks.Socks4Protocol(proxy=proxy, proxy_auth=auth, waiter=waiter, dst=dst, app_protocol_factory=client_factory)


class StreamProtocol(asyncio.Protocol):
    '''Simple connection protocol between server and client connection'''
    def __init__(self, peer_transport):
        self._transport = None
        self._peer_transport = peer_transport

    def session_started(self):
        '''asyncssh related function'''

    # pylint: disable=arguments-differ,unused-argument
    def data_received(self, data, datatype=None):
        self._peer_transport.write(data)

    def connection_lost(self, exc):
        self._peer_transport.close()

    def connection_made(self, transport):
        self._transport = transport


class BaseProxyServer(asyncio.Protocol):
    '''Base proxy server'''
    def __init__(self, rserver: list[BaseClient]):
        self.log = logging.getLogger(__class__.__name__)
        self._loop = asyncio.get_event_loop()
        self._rserver = rserver
        self._direct = BaseClient.connection()
        self._transport: asyncio.Transport
        self._remote_transport: asyncio.Transport
        self._remote_protocol: asyncio.BaseProtocol

    def schedule(self, host: str) -> BaseClient:
        '''choose remote protocol or use direct'''
        return next((x for x in self._rserver if x.match_rule(host)), self._direct)

    def connection_made(self, transport: asyncio.Transport):
        self._transport = transport

    def connection_lost(self, exc):
        self._transport.close()

    def _update_transport_protocol(self):
        stream_protocol = StreamProtocol(self._remote_transport)
        self._transport.set_protocol(stream_protocol)
        self._remote_transport.resume_reading()

    async def _create_remote_connection(self, dhost: str, dport: int):
        protocol = self.schedule(dhost)
        self.log.debug('[%s] %s:%s', protocol.log.name, dhost, dport)
        try:
            self._remote_transport, self._remote_protocol = await protocol.create_connection(
                lambda: StreamProtocol(self._transport),
                host=dhost,
                port=dport
            )
            self._remote_transport.pause_reading()
        except (TimeoutError, RuntimeError, OSError, asyncssh.misc.Error, aiosocks.SocksError, asyncio.TimeoutError) as ex:
            self.log.exception('create remote connection %s:%s %s', protocol.hosts.print(dhost), dport, ex, exc_info=None)
            protocol.hosts.rotate(dhost)
            raise
        except Exception:
            self.log.exception('unknown error connecting %s:%s', protocol.hosts.print(dhost), dport)
            raise

class HTTPServer(BaseProxyServer):
    '''HTTP proxy server'''
    def __init__(self, rserver: list[BaseClient]):
        super().__init__(rserver=rserver)
        self.__connected = False
        self.__established = False
        self.__buffer = []

    def data_received(self, data):
        if data[0:4] in (b'GET ', b'HEAD', b'POST', b'PUT ', b'DELE', b'OPTI', b'TRAC', b'PATC'):
            self.log = logging.getLogger(__class__.__name__)
            self.__connected = True
            self.__established = False
            self.__handle_request(data)
        elif self.__connected:
            if self.__established:
                self._remote_transport.write(data)
            else:
                self.__buffer.append(data)
        else:
            super().data_received(data)

    def __handle_request(self, data: bytes):
        body = HttpBody(data)

        def established_callback(task:asyncio.Task):
            self.__established = True
            self._remote_transport.resume_reading()
            if task.exception() is None:
                self._remote_transport.write(bytes(body))
                for i in self.__buffer:
                    self._remote_transport.write(i)
                self.__buffer = []
            elif not self._transport.is_closing():
                self._transport.write(body.ver + b' 503 Service Unavailable\r\n\r\n')
                self._transport.close()

        self._loop.create_task(
            self._create_remote_connection(body.url.hostname, body.url.port)
        ).add_done_callback(established_callback)


class ConnectServer(BaseProxyServer):
    '''HTTP CONNECT proxy server'''
    def data_received(self, data):
        if data.startswith(b'CONNECT '):
            self.log = logging.getLogger(__class__.__name__)
            self.__handle_request(data)
        else:
            super().data_received(data)

    def __handle_request(self, data: bytes):
        body = HttpBody(data)

        def established_callback(task:asyncio.Task):
            if task.exception() is None:
                self._transport.write(body.ver + b' 200 Connection established\r\nConnection: close\r\n\r\n')
                self._update_transport_protocol()
            elif not self._transport.is_closing():
                self._transport.write(body.ver + b' 503 Service Unavailable\r\n\r\n')
                self._transport.close()

        self._loop.create_task(
            self._create_remote_connection(body.url.hostname, body.url.port)
        ).add_done_callback(established_callback)


class Socks4Server(BaseProxyServer):
    '''Socks4 proxy server'''
    def data_received(self, data):
        if data[0] == 4:
            self.log = logging.getLogger(__class__.__name__)
            self.__handle_request(data)
        else:
            super().data_received(data)

    def __handle_request(self, data: bytes):
        if data[1] == 1:    #connect
            port = int.from_bytes(data[2:4], 'big')
            host = socket.inet_ntop(socket.AF_INET, data[4:8])
            assert data[8] == 0

            def established_callback(task:asyncio.Task):
                if task.exception() is None:
                    self._transport.write(b'\x00\x5a' + data[2:8])
                    self._update_transport_protocol()
                elif not self._transport.is_closing():
                    self._transport.write(b'\x00\x5b' + data[2:8])
                    self._transport.close()

            self._loop.create_task(
                self._create_remote_connection(host, port)
            ).add_done_callback(established_callback)


class Socks5Server(BaseProxyServer):
    '''Socks5 proxy server'''
    INIT, HOST, DATA = 0, 1, 2

    def __init__(self, rserver: list[BaseClient]):
        super().__init__(rserver=rserver)
        self.__state = self.INIT

    def data_received(self, data):
        if data[0] == 5:
            self.log = logging.getLogger(__class__.__name__)
            self.__handle_request(data)
        else:
            super().data_received(data)

    def __handle_request(self, data: bytes):
        if self.__state == self.INIT:
            self._transport.write(b'\x05\x00')  # no auth
            self.__state = self.HOST

        elif self.__state == self.HOST:
            ver, cmd, _, atype = data[:4]
            assert ver == 0x05 and cmd == 0x01

            if atype == 3:    # domain
                length = data[4]
                hostname, nxt = data[5:5+length].decode(), 5+length
            elif atype == 1:  # ipv4
                hostname, nxt = socket.inet_ntop(socket.AF_INET, data[4:8]), 8
            elif atype == 4:  # ipv6
                hostname, nxt = socket.inet_ntop(socket.AF_INET6, data[4:20]), 20
            else:
                raise Exception(f"Socks5 unknown {atype=}")
            port = int.from_bytes(data[nxt:nxt+2], 'big')

            def established_callback(task:asyncio.Task):
                if task.exception() is None:
                    self._transport.write(b'\x05\x00\x00' + data[3:nxt+2])
                    self._update_transport_protocol()
                elif not self._transport.is_closing():
                    self._transport.write(b'\x05\x04\x00' + data[3:nxt+2])
                    self._transport.close()

            self._loop.create_task(
                self._create_remote_connection(hostname, port)
            ).add_done_callback(established_callback)


# pylint: disable=too-many-ancestors
class ProxyServer(
    Socks4Server,
    HTTPServer,
    ConnectServer,
    Socks5Server,
):
    '''Auto select proxy server type class'''
