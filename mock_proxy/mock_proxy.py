#!/usr/bin/env python3
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
# pylint: disable=protected-access, consider-using-f-string

from functools import reduce
import logging
import asyncio
import ssl
import json
import io
import os
import sys
import re
import ast
import time
import random
import base64
from typing import Awaitable, Callable, Dict, List, Optional, Any, AsyncGenerator, Tuple, TypeVar, Union, cast
from collections import defaultdict
import yarl
import yaml
import aiohttp
from aiohttp import web, web_urldispatcher, typedefs
from multidict import CIMultiDict
try:
    from aiohttp_sse import sse_response, EventSourceResponse
    SSE = True
except ModuleNotFoundError:
    print('WARN: aiohttp_sse not installed. SSE functionallity disabled')
    SSE = False

StringT = TypeVar('StringT', bound=Optional[str])

def strtobool(val:Union[str,bool]):
    if isinstance(val, bool):
        return val
    lval = val.lower()
    if lval in ('y', 'yes', 't', 'true', 'on', '1'):
        return True
    elif lval in ('n', 'no', 'f', 'false', 'off', '0'):
        return False
    else:
        return val

class MultisubscriberQueue:
    """ MultisubscriberQueue """
    def __init__(self):
        self.subscribers: List[asyncio.Queue] = []

    async def subscribe(self) -> AsyncGenerator:
        """
        Subscribe to data using an async generator
        Example:
            with MultisubscriberQueue.subscribe() as data:
                print(data)
        """
        _queue: asyncio.Queue = asyncio.Queue()
        try:
            self.subscribers.append(_queue)
            while True:
                _data: Any = await _queue.get()
                if _data is StopAsyncIteration:
                    break
                yield _data
        finally:
            self.subscribers.remove(_queue)

    async def put(self, data: Any) -> None:
        """ Put new data on all subscriber queues """
        for _queue in self.subscribers:
            await _queue.put(data)

    async def close(self) -> None:
        """ Force clients using MultisubscriberQueue.subscribe() to end iteration """
        await self.put(StopAsyncIteration)


class ProxyChain:
    """
    socket chain for forward logging via http connect
    """
    _chain: Dict[str,str] = {}

    def __init__(self, client_t:Optional[asyncio.BaseTransport], proxy_t:Optional[asyncio.BaseTransport]):
        assert client_t
        assert proxy_t
        self._context = '%s:%d' % proxy_t.get_extra_info('sockname')[:2]
        ProxyChain._chain[self._context] = '%s:%d' % client_t.get_extra_info('peername')[:2]

    @staticmethod
    def get(client_t:Optional[asyncio.BaseTransport]) -> str:
        """get peer host:port string from asyncio.Transport"""
        assert client_t
        _id:str = '%s:%d' % client_t.get_extra_info('peername')[:2]
        if _id in ProxyChain._chain:
            _id = f'{_id}[{ProxyChain._chain[_id]}]'
        return _id

    def __enter__(self):
        return self

    def __exit__(self, *args):
        del ProxyChain._chain[self._context]


class ProxyResponse(web.Response):
    """
    Response with disabled additional aiohttp headers
    """
    async def _prepare_headers(self) -> None:
        headers = self._headers
        self._headers = CIMultiDict(headers)
        await super()._prepare_headers()
        self._headers = headers


class StreamProtocol(asyncio.Protocol):
    '''Simple connection protocol between server and client connection'''
    def __init__(self, peer_transport:asyncio.Transport, waiter:asyncio.Event):
        self._transport = None
        self._peer_transport = peer_transport
        self._waiter = waiter

    def data_received(self, data):
        self._peer_transport.write(data)

    def connection_lost(self, exc):
        self._waiter.set()
        self._peer_transport.close()

    def connection_made(self, transport):
        self._transport = transport


class DefaultResource(web_urldispatcher.Resource):
    """
    default route functionality for aiohttp URL dispatcher
    """
    def _match(self, path: str):
        return {}

    def add_prefix(self, prefix: str) -> None:
        pass

    @property
    def canonical(self) -> str:
        return "*"

    def get_info(self) -> web_urldispatcher._InfoDict:
        return {"path": "*"}

    def raw_match(self, path: str) -> bool:
        return path == '*'

    def url_for(self, **kwargs: str) -> yarl.URL:
        return yarl.URL()


class UrlDispatcher(web_urldispatcher.UrlDispatcher):
    """
    URL dispatcher with DefaultResource support
    """
    def add_resource(self, path: str, *, name: Optional[str] = None) -> web_urldispatcher.Resource:
        if path == "*":
            resource = DefaultResource()
            self.register_resource(resource)
            return resource

        return super().add_resource(path, name=name)

    def add_connect(self, path: str, handler: typedefs.Handler, **kwargs: Any) -> web_urldispatcher.AbstractRoute:
        """Shortcut for add_route with method CONNECT."""
        return self.add_route(aiohttp.hdrs.METH_CONNECT, path, handler, **kwargs)


class CIDefaultMultiDict(CIMultiDict):
    """ multidict + defaultdict """
    def __getitem__(self, key):
        return self.getone(key, None)


class SafeDict(dict):
    """ helper class for yamlEnv """
    def __init__(self, arg:Optional[dict]=None):
        if arg is None:
            super().__init__()
        else:
            super().__init__(arg)

    def __missing__(self, key):
        return '{' + key + '}'


class YamlEnv:
    """ yaml !env {} variable functionality """
    _globals = SafeDict()
    pattern = re.compile(r'.*{.*}.*')
    def __init__(self, value:str):
        self.value = value
    def __repr__(self):
        return f"'{self.value.format_map(self._globals)}'"
    def __str__(self):
        try:
            return self.value.format_map(self._globals)
        except (AttributeError, TypeError):
            return self.value
    def render(self, kwargs:Optional[Dict]) -> str:
        """ render template string using yaml !bind data and kwargs """
        try:
            if kwargs is None:
                kwargs = {}
            return str(Handlers.get(f'f"""{self.value}"""', **kwargs)[0])
        except (ValueError, AttributeError):
            return self.value


class JSONEncoder(json.JSONEncoder):
    """ YamlEnv json renderer """
    def __init__(self, local:Optional[Dict]=None):
        if local is None:
            self._local = {}
        else:
            self._local = local
        super().__init__()
    def default(self, o):
        if isinstance(o, YamlEnv):
            return Handlers.get(o.value, **self._local)[0]
        return super().default(o)


class Handlers:
    """
    mock proxy handlers collection
    """
    staticmethods:Dict[str, Dict] = {}
    _binOps = {
        ast.cmpop: Exception,
        ast.Eq: lambda a, b: a == b,
        ast.NotEq: lambda a, b: a != b,
        ast.Lt: lambda a, b: a < b,
        ast.LtE: lambda a, b: a <= b,
        ast.Gt: lambda a, b: a > b,
        ast.GtE: lambda a, b: a >= b,
        ast.Is: lambda a, b: a is b,
        ast.IsNot: lambda a, b: a is not b,
        ast.In: lambda a, b: a in b,
        ast.NotIn: lambda a, b: a not in b,
        ast.boolop: Exception,
        ast.And: all,
        ast.Or: lambda x: reduce(lambda a,b: a or b, x, False),
        ast.unaryop: Exception,
        ast.Invert: lambda a: ~a,
        ast.Not: lambda a: not a,
        ast.UAdd: lambda a: +a,
        ast.USub: lambda a: -a,
        ast.operator: Exception,
        ast.Add: lambda a, b: a + b,
        ast.BitAnd: lambda a, b: a & b,
        ast.BitOr: lambda a, b: a | b,
        ast.BitXor: lambda a, b: a ^ b,
        ast.Div: lambda a, b: a / b,
        ast.FloorDiv: lambda a, b: a // b,
        ast.LShift: lambda a, b: a << b,
        ast.Mod: lambda a, b: a % b,
        ast.Mult: lambda a, b: a * b,
        ast.MatMult: lambda a, b: a @ b,
        ast.Pow: lambda a, b: a ** b,
        ast.RShift: lambda a, b: a >> b,
        ast.Sub: lambda a, b: a - b,
    }
    @classmethod
    def get(cls, handler:Union[str,list,dict], **local) -> Tuple[typedefs.Handler, Optional[str]]:
        """
        safe eval for Handlers class methods:
        Handlers.get('send') similar eval('send') with additional checks
        """
        def _eval(node:Optional[ast.AST]) -> Any:
            nonlocal local
            if node is None:
                return None
            if isinstance(node, ast.Expression):
                return _eval(node.body)
            if isinstance(node, ast.Constant):
                if isinstance(node.value, str):
                    return YamlEnv(node.value) if YamlEnv.pattern.match(node.value) else node.value
                return node.value
            if isinstance(node, ast.Subscript):
                if isinstance(node.ctx, ast.Load):
                    if isinstance(node.slice, ast.Slice):
                        return _eval(node.value)[_eval(node.slice.lower):_eval(node.slice.upper):_eval(node.slice.step)]
                    return _eval(node.value)[_eval(node.slice)]
                raise SyntaxError(f"Unsupported Subscript ctx {node.ctx.__class__}")
            if isinstance(node, ast.Call):
                args = [_eval(x) for x in node.args]
                kwargs = {x.arg:_eval(x.value) for x in node.keywords if x.arg}
                return _eval(node.func)(*args, **kwargs)
            if isinstance(node, ast.Name):
                if node.id in cls.staticmethods:
                    local = {**{'prefix': node.id}, **cls.staticmethods[node.id], **local}
                    return local.pop('__handler')
                if node.id in local:
                    return local[node.id]
                raise SyntaxError(f"Unknown variable {node.id}")
            if isinstance(node, ast.Compare):
                left = strtobool(_eval(node.left))
                for right in node.comparators:
                    right = strtobool(_eval(right))
                    ops = node.ops.pop(0)
                    if Handlers._binOps[ops.__class__](left, right) is False:
                        return False
                    left = right
                return True
            if isinstance(node, ast.BoolOp):
                values = [_eval(x) for x in node.values]
                return Handlers._binOps[node.op.__class__](values)
            if isinstance(node, ast.UnaryOp):
                return Handlers._binOps[node.op.__class__](_eval(node.operand))
            if isinstance(node, ast.BinOp):
                return Handlers._binOps[node.op.__class__](_eval(node.left), _eval(node.right))
            if isinstance(node, ast.FormattedValue):
                return _eval(node.value)
            if isinstance(node, ast.JoinedStr):
                return ''.join([str(_eval(x)) for x in node.values])
            if isinstance(node, ast.List):
                return [_eval(x) for x in node.elts]
            if isinstance(node, ast.Dict):
                return {_eval(k):_eval(v) for k,v in zip(node.keys, node.values)}
            if isinstance(node, ast.Attribute):
                value = _eval(node.value)
                if hasattr(value, node.attr):
                    return getattr(value, node.attr)
                raise AttributeError(f"object has no attribute {node.attr}")
            raise SyntaxError(f"Bad syntax, {type(node)}")

        if isinstance(handler, (str, YamlEnv)):
            method = _eval(ast.parse(str(handler), mode='eval'))
        elif isinstance(handler, list):
            local['prefix'] = 'switch'
            local['logtail'] = False
            method = switch(handler, **local)
        elif isinstance(handler, dict):
            local['prefix'] = 'response'
            method = status(local=local, **handler)
        else:
            raise Exception(f'{handler} incompatible type. Supported: dict, str or list')

        if local.pop('log', True) and local.get('prefix'):
            method = cls._httplog(method, **local)
        return (method, local.pop('prefix', None))

    @staticmethod
    async def log_head(request:web.Request, peer, prefix):
        """log aiohttp.web.Request"""
        body = await request.text()
        logging.info('%s C->P %s %s %s %s\nheaders:\n  %s%s',
            prefix, peer, request.method, request.url, request.version,
            '\n  '.join([f'{key}: {value}' for key, value in request.headers.items()]),
            f'\nbody:\n{body}' if body else ''
        )

    @staticmethod
    def log_tail(response:web.StreamResponse, peer, prefix, omit=100):
        """log aiohttp.web.Response"""
        body = response._body
        if isinstance(body, aiohttp.payload.Payload):
            body = body._value

        if body is not None and isinstance(body, (bytearray, bytes)):
            if logging.getLogger().level >= logging.DEBUG and len(body) > omit:
                body = body[:omit] + b'<omited by loglevel>'

            if response.charset:
                try:
                    body = body.decode(response.charset)
                except UnicodeDecodeError:
                    pass

        assert response._req
        logging.info('%s P->C: %s status %s %s %s\nheaders:\n  %s%s',
            prefix, peer,
            response.status, response.reason, response._req.version,
            '\n  '.join([f'{key}: {value}' for key, value in response.headers.items()]),
            f'\nbody:\n{body}' if body else '',
        )

    @staticmethod
    def _httplog(func:Callable[[web.Request], Awaitable[web.StreamResponse]], **kwargs):
        async def _wrapper(request:web.Request) -> web.StreamResponse:
            peer = ProxyChain.get(request.transport)
            prefix = kwargs.get('prefix', func.__name__)
            if kwargs.get('loghead', True) is True:
                await Handlers.log_head(request, peer, prefix)

            response = None
            try:
                response = await func(request)
                return response
            finally:
                if kwargs.get('logtail', True) is True:
                    if response is None or response.prepared is True:
                        logging.info('%s connection %s closed', prefix, peer)
                    else:
                        await response.prepare(request)
                        Handlers.log_tail(response, peer, prefix, kwargs.get('omit', 100))
        return _wrapper

    @classmethod
    # pylint: disable=unused-argument
    def callable(cls, log=True, omit=100):
        """ register function in Handlers """
        kwargs = dict(locals())
        del kwargs['cls']
        def decorator(handler:Callable[..., Any]) -> Callable[..., Any]:
            kwargs['__handler'] = handler
            cls.staticmethods[handler.__name__] = kwargs
            return handler
        return decorator

    @staticmethod
    def formatter_constructor(request:web.Request, **local) -> dict:
        """ prepare data for render tamplates from http request """
        return dict(
                qs=('?' + request.query_string) if request.query_string else '',
                query=request.query,
                url=request.url,
                path=request.raw_path,
                path_qs=request.path_qs,
                headers=CIDefaultMultiDict(request.headers),
                **request.match_info,
                **local
            )

    @staticmethod
    def compile_str(url:Union[None, str, YamlEnv], request:web.Request, **local) -> Optional[str]:
        """ render templates using http request data """
        if isinstance(url, YamlEnv):
            return url.render(Handlers.formatter_constructor(request, **local))
        return url


def switch(script:List[Union[str, Dict]], root=True, **kwargs):
    """
    handler:
    - case: body['server']['availability_zone'] == 'AZ#2222'
        then:
        status: 300
    - case: body['server']['availability_zone'] == 'AZ#9999'
        then: forward("https://ipaddress:8774{path_qs}")
    - then:
        status: 400
        text: HTTP 400
    """
    def default():
        return defaultdict(default)

    def loads(data):
        return json.loads(data, object_pairs_hook=lambda pair: defaultdict(default, pair))

    async def _switch(request:web.Request) -> web.StreamResponse:
        peer = ProxyChain.get(request.transport)
        local = {} if root else kwargs
        local['log'] = False # log can be provided by kwargs
        try:
            local['body'] = await request.json(loads=loads) if request.body_exists else loads('{}')
        except json.JSONDecodeError:
            local['body'] = loads('{}')

        ret = web.Response()
        prefix = 'switch'
        for step in script:
            if isinstance(step, dict):
                if 'case' in step:
                    if Handlers.get(step['case'], **Handlers.formatter_constructor(request, **local))[0] is False:
                        continue

                if 'then' in step:
                    (handler, prefix) = Handlers.get(step['then'], root=False, **local)
                    ret = await handler(request)
                    break
            else:
                (handler, prefix) = Handlers.get(step, root=False, **local)
                ret = await handler(request)
                response = {}
                response['status'] = ret.status
                response['headers'] = CIDefaultMultiDict(ret.headers)

                if isinstance(ret, web.Response):
                    try:
                        response['body'] = loads(ret.text)
                    except (json.JSONDecodeError, TypeError):
                        response['body'] = ret.text

                local['response'] = defaultdict(lambda: None, response)

        if ret.prepared is False:
            await ret.prepare(request)
            Handlers.log_tail(ret, peer, prefix)
        elif root is True:
            logging.info('%s connection %s closed', prefix, peer)

        return ret
    return _switch

@Handlers.callable(log=False)
def rnd(stop:int):
    """
    - path: /rnd
      method: GET
      handler:
      - case: rnd(4) == 0
        then:
          status: 500
      - then:
          status: 200
    """
    return random.randrange(stop)

access_tokens = {}

@Handlers.callable(log=False)
def token(prefix=None, expires:int=0):
    """
    Sample usage:
    - path: /token
      method: GET
      handler:
        body:
          access_token: f"{token(expires=1800)}"
          expires_in: 1800
    - path: /check
        method: GET
        handler:
        - case: check_token(headers["Authorization"])
          then:
            status: 200
        - then:
            status: 401
    """
    access_token = base64.b64encode(random.randbytes(20)).decode()
    if prefix:
        key = f'{prefix} {access_token}'
    else:
        key = access_token

    if expires > 0:
        value = time.time() + expires
    else:
        value = None
    access_tokens[key] = value
    return access_token

@Handlers.callable(log=False)
def check_token(key:str):
    """
    see 'token' example
    """
    if key in access_tokens:
        if access_tokens[key] is None or access_tokens[key] > time.time():
            return True
        del access_tokens[key]
    return False

@Handlers.callable()
async def ws(request:web.Request) -> web.StreamResponse:
    """
    WebSocket server endpoint
    """
    prefix = 'ws'
    peer = ProxyChain.get(request.transport)
    response = web.WebSocketResponse()
    await response.prepare(request)
    Handlers.log_tail(response, peer, prefix)

    async def sender():
        async for data in request.app['ws_queue'].subscribe():
            await response.send_str(data)

    task = asyncio.create_task(sender())
    try:
        async for data in response:
            logging.info('%s C->P: %s data: %s', prefix, peer, data)
            if data.data == 'X':
                reply_data = b''
                logging.info('%s P->C: %s data: %s', prefix, peer, reply_data)
                await response.send_bytes(reply_data)
    finally:
        task.cancel()
        await task
    return response

@Handlers.callable()
async def send(request:web.Request) -> web.StreamResponse:
    """
    broadcast messages to all SSE and WS clients
    Sample usage:
    - method: POST
      path: /send
      handler: send
    """
    data = await request.text()
    if SSE:
        await request.app['sse_queue'].put(data)
    await request.app['ws_queue'].put(data)
    return web.Response(text='OK')

@Handlers.callable()
async def wssend(request:web.Request) -> web.StreamResponse:
    """
    broadcast messages to all WS clients
    """
    data = await request.text()
    await request.app['ws_queue'].put(data)
    return web.Response(text='OK')

if SSE:
    @Handlers.callable()
    async def sse(request:web.Request) -> web.StreamResponse:
        """
        SSE server endpoint
        """
        peer = ProxyChain.get(request.transport)
        async with sse_response(request) as response: # type: ignore
            response: EventSourceResponse = response # type: ignore
            Handlers.log_tail(response, peer, 'sse')

            response.ping_interval = 3600
            try:
                async for data in request.app['sse_queue'].subscribe():
                    await response.send(re.sub(r'[\r\n]+\s*', ' ', data))
                    #await response.send(data)
            except asyncio.CancelledError:
                pass
            return response

    @Handlers.callable()
    async def ssesend(request:web.Request) -> web.StreamResponse:
        """
        broadcast messages to all SSE clients
        """
        data = await request.text()
        await request.app['sse_queue'].put(data)
        return web.Response(text='OK')

@Handlers.callable()
def sleep(timeout:Optional[int]=None) -> typedefs.Handler:
    """
    http throttling
    """
    async def _sleep(request:web.Request) -> web.StreamResponse:
        peer = ProxyChain.get(request.transport)
        start_time = time.time()
        logging.info('sleep for %s session %s', timeout, peer)
        try:
            if timeout is None:
                while True:
                    await asyncio.sleep(1)
            else:
                await asyncio.sleep(timeout)
        except asyncio.CancelledError:
            pass
        end_time = time.time()
        return web.Response(text=f'sleep {end_time - start_time} seconds')
    return _sleep

@Handlers.callable()
def status(body=None, local=None, **handler):
    """
    return custom response
    """
    if local is None:
        local = {}
    async def _status(request:web.Request):
        if isinstance(body, (list, dict)):
            return web.json_response(body, dumps=JSONEncoder(Handlers.formatter_constructor(request, **local)).encode, **handler)
        return web.Response(text=Handlers.compile_str(body, request, **local), **handler)
    return _status

@Handlers.callable()
def load(file, **kwargs):
    """
    return file contents
    Sample usage:
    - method: GET
      path: /bigfile
      handler: load('bigfile.txt')
    """
    with open(file, encoding='utf-8') as fp:
        contents = fp.read()
    async def _load(request:web.Request):
        return web.Response(text=contents, **kwargs)
    return _load

@Handlers.callable()
def connect(host:str, port:int) -> typedefs.Handler:
    """
    http connect
    Sample config:
    ---
    listen:
    - port: 8080
    - port: 8443
      ssl:
        certfile: "/etc/ssl/certs/ssl-cert-snakeoil.pem"
        keyfile: "/etc/ssl/private/ssl-cert-snakeoil.key"
    routes:
    - method: CONNECT
      path: "*"
      handler: connect("localhost", 8443)
    - method: "*"
      path: "*"
      handler: proxy

    Usage:
    http_proxy=localhost:8080 https_proxy=localhost:8080 curl -k <URL>
    """
    async def _connect(request:web.Request) -> web.StreamResponse:
        loop = asyncio.get_event_loop()
        reqest_transport = request.content._protocol.transport
        assert reqest_transport

        waiter = asyncio.Event()
        remote_transport, _ = await loop.create_connection(
            lambda: StreamProtocol(reqest_transport, waiter),
            host=host,
            port=port,
        )

        remote_transport = cast(asyncio.Transport, remote_transport)
        peer = ProxyChain.get(request.transport)

        with ProxyChain(request.transport, remote_transport):
            reqest_transport.set_protocol(StreamProtocol(remote_transport, waiter))

            response = web.StreamResponse(status=200, reason='Connection established', headers={aiohttp.hdrs.CONNECTION:'Close'})
            await response.prepare(request)
            Handlers.log_tail(response, peer, 'connect')

            waiter.clear()
            await waiter.wait()
            return response

    return _connect

@Handlers.callable()
def forward(url:Union[str,YamlEnv], logname:Optional[str]='forward', stream=False) -> typedefs.Handler:
    """
    forward direct request to other host
    Sample usage:
    - method: "*"
      path: "*"
      handler: forward("http://localhost:8000{path_qs}")
    """
    async def _forward(request:web.Request) -> web.StreamResponse:
        peer = ProxyChain.get(request.transport)

        async with aiohttp.ClientSession(
            auto_decompress=True,
            skip_auto_headers=[
                aiohttp.hdrs.CONTENT_TYPE,
                aiohttp.hdrs.USER_AGENT,
                aiohttp.hdrs.ACCEPT_ENCODING,
            ],
        ) as session:
            async with session.request(request.method,
                str(Handlers.compile_str(url, request)),
                headers=request.headers,
                data=await request.read(),
                ssl=False,
                allow_redirects=False,
            ) as client_resp:
                logging.debug('%s P->S: %s %s %s %s\nheaders:\n  %s',
                    logname,
                    peer,
                    client_resp.request_info.method, client_resp.request_info.url, session.version,
                    '\n  '.join([f'{key}: {value}' for key, value in client_resp.request_info.headers.items()]),
                )
                logging.debug('%s S->P: %s status %s %s %s\nheaders:\n  %s',
                    logname, peer,
                    client_resp.status, client_resp.reason, client_resp.version,
                    '\n  '.join([f'{key}: {value}' for key, value in client_resp.headers.items()]),
                )

                response = ProxyResponse(status=client_resp.status, headers=client_resp.headers)
                if stream:
                    await response.prepare(request)
                    Handlers.log_tail(response, peer, logname)
                    try:
                        async for chunk, _ in client_resp.content.iter_chunks():
                            logging.info('%s P->C: %s chunk: %s', logname, peer, chunk)
                            await response.write(chunk)
                    finally:
                        pass
                else:
                    response.body = await client_resp.read()
                    if client_resp.headers.get(aiohttp.hdrs.TRANSFER_ENCODING) == 'chunked':
                        response.enable_chunked_encoding()

                return response

    return _forward

@Handlers.callable()
async def proxy(request:web.Request) -> web.StreamResponse:
    """
    simple http proxy
    CONNECT method for https does not supported
    Sample usage:
    - method: "*"
      path: "*"
      handler: proxy
    """
    return await forward(YamlEnv('{url}'), 'proxy')(request)

def yaml_variables():
    '''
    Extend yaml loader with !include and !var constructors
    Usage:
    var = yaml_variables()
    data = yaml.safe_load("included: !include included.yaml\nfoo: ! '{bar}'\nfoo2: !var '{bar}'\nbar: var{bar}")
    var['bar'] = 'test'
    print(json.dumps(data))
    var['bar'] = 'not test'
    print(data)
    '''
    class Struct:
        '''dictionary['key'] to dictionary.key convertion'''
        def __init__(self, entries):
            self.__dict__.update(entries)

    def var_constructor(loader:yaml.SafeLoader, node:yaml.ScalarNode):
        value = loader.construct_yaml_str(node)
        return YamlEnv(value)

    def var_representer(dumper:yaml.SafeDumper, data:YamlEnv):
        return dumper.represent_scalar('!var', str(data))

    def include_constructor(loader: yaml.SafeLoader, node: yaml.ScalarNode):
        stream = cast(io.TextIOWrapper, loader.stream)
        _root = os.path.split(stream.name)[0] if loader.stream else '.'
        filename = os.path.join(_root, str(loader.construct_scalar(node)))
        try:
            with open(filename, 'r', encoding='utf-8') as file_object:
                return yaml.safe_load(file_object)
        except FileNotFoundError:
            logging.error('included file not found: %s', filename)
            return {}

    def join_constructor(loader: yaml.SafeLoader, node: yaml.SequenceNode):
        seq = loader.construct_sequence(node)
        return ''.join([str(i) for i in seq])

    def bind_constructor(loader: yaml.SafeLoader, node: yaml.MappingNode):
        seq = loader.construct_mapping(node, deep=True)
        for key, value in seq.items():
            if isinstance(value, dict):
                YamlEnv._globals[key] = Struct(value)
            else:
                YamlEnv._globals[key] = value
        return seq

    yaml.SafeLoader.add_constructor('!var', var_constructor)
    yaml.SafeLoader.add_implicit_resolver('!var', YamlEnv.pattern, None)
    yaml.SafeLoader.add_constructor('!include', include_constructor)
    yaml.SafeLoader.add_constructor('!join', join_constructor)
    yaml.SafeLoader.add_constructor('!bind', bind_constructor)
    yaml.SafeDumper.add_representer(YamlEnv, var_representer)
    json._default_encoder = JSONEncoder()  # type: ignore
    json.JSONEncoder = JSONEncoder

    return YamlEnv._globals


def main():
    """ entry point """
    logging.addLevelName(logging.DEBUG - 5, 'TRACE')
    logging.basicConfig(format='%(asctime)s %(levelname)s:%(name)s: %(message)s')
    logging.getLogger().setLevel(logging.getLevelName(os.environ.get('LOG_LEVEL', 'INFO')))

    yaml_variables()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    cfg = [{
        'listen': [
            {
                'port': 7080,
            },
            {
                'port': 7443,
                'ssl': [{
                    'certfile': '/etc/ssl/certs/ssl-cert-snakeoil.pem',
                    'keyfile': '/etc/ssl/private/ssl-cert-snakeoil.key',
                },
                {
                    'certfile': '/etc/pki/tls/certs/ssl-cert-snakeoil.pem',
                    'keyfile': '/etc/pki/tls/private/ssl-cert-snakeoil.key',
                }]
            }
        ],
        'routes': [
            {
                'method': 'GET',
                'path': '/ws',
                'handler': 'ws',
            },
            {
                'method': 'POST',
                'path': '/send',
                'handler': 'send',
            },
            {
                'method': '*',
                'path': '*',
                'handler': 'forward("http://localhost:8000{path_qs}")',
            },
        ]
    }]

    def loadconfig(default):
        cfg = default
        argcfg = sys.argv[1] if len(sys.argv) == 2 else None
        defcfg = 'mock_proxy.yaml'

        if argcfg and os.path.isfile(argcfg):
            logging.info('using config from args: %s', argcfg)
            return yaml.safe_load(open(argcfg, encoding='utf-8'))

        if 'MOCK_PROXY' in os.environ:
            logging.info('using config from MOCK_PROXY: %s', os.environ['MOCK_PROXY'])
            if os.path.isfile(os.environ['MOCK_PROXY']):
                return yaml.safe_load(open(os.environ['MOCK_PROXY'], encoding='utf-8'))
            return json.loads(os.environ['MOCK_PROXY'])

        if os.path.isfile(defcfg):
            logging.info('using default config file: %s', defcfg)
            return yaml.safe_load(open(defcfg, encoding='utf-8'))

        logging.info('using default config')
        return cfg

    cfg = loadconfig(cfg)

    if not isinstance(cfg, list):
        cfg = [cfg]

    logging.info('effective config:\n%s', yaml.safe_dump(cfg))

    def route_compile(route:Dict[str,str]) -> web.RouteDef:
        return web.route(str(route['method']), str(route['path']), Handlers.get(route['handler'])[0])

    async def create_queue(app:web.Application):
        if SSE:
            app['sse_queue'] = MultisubscriberQueue()
        app['ws_queue'] = MultisubscriberQueue()

    async def close_queue(app:web.Application):
        if SSE:
            await app['sse_queue'].close()
        await app['ws_queue'].close()

    runners:List[web.AppRunner] = []
    for cfg_unit in cfg:
        app = web.Application()
        app._router = UrlDispatcher()
        app.add_routes([route_compile(route) for route in cfg_unit.get('routes', [])])

        app.on_startup.append(create_queue)
        app.on_shutdown.append(close_queue)
        runner = web.AppRunner(app, access_log=None, handler_cancellation=True)
        loop.run_until_complete(runner.setup())
        runners.append(runner)

        for listen in cfg_unit.get('listen', []):
            ssl_context = None
            if 'ssl' in listen:
                if not isinstance(listen['ssl'], (list, tuple)):
                    listen['ssl'] = [listen['ssl']]
                for ssl_config in listen['ssl']:
                    try:
                        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                        ssl_context.load_cert_chain(**ssl_config)
                        break
                    except FileNotFoundError:
                        pass
                else:
                    raise FileNotFoundError(f"No such file or directory: {listen['ssl']}")
            site = web.TCPSite(runner, listen.get('host'), listen['port'], ssl_context=ssl_context, reuse_port=True)
            loop.run_until_complete(site.start())

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for runner in runners:
            loop.run_until_complete(runner.cleanup())
        loop.close()


if __name__ == '__main__':
    main()
