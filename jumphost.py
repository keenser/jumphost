#!/usr/bin/env python3
#
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
#
'''
start http+socks5 proxy over several ssh tunnels
'''
import asyncio
from functools import partial
import logging
import logging.handlers
import re
import io
import os
import sys
import glob
import signal
import argparse
from typing import Any, Optional, Sequence, Dict, cast
import yaml
import proxy
import pykeepass
import pykeepass.group
if sys.platform == 'linux':
    import uvloop
    import daemon
    import daemon.pidfile
    import setproctitle
    import pwd
    import grp

PKG_VERSION = "4.1"
SERVICE_NAME = "jumphost"
SERVICE_DESC = "start http+socks5 proxy over several ssh tunnels"


def getoptions(args: Optional[Sequence[str]]=None):
    '''parse command options'''
    parser = argparse.ArgumentParser(
        description=f"{SERVICE_DESC} {PKG_VERSION}"
    )

    parser.add_argument("-v", "--verbose",
        dest="verbosity",
        action="count",
        help="print more diagnostic messages (option can be given multiple times)",
        default=0
    )

    parser.add_argument("-l", "--log",
        dest="logfile",
        nargs="?",
        help="log file, default: %(default)s, %(const)s if enabled",
        const=f"/var/log/{SERVICE_NAME}/{SERVICE_NAME}.log"
    )

    if sys.platform == 'linux':
        parser.add_argument("-s", "--syslog",
            dest="syslog",
            action="store_true",
            help="log to syslog (default %(default)s)",
            default=False
        )

        parser.add_argument("-p", "--pid",
            dest="pid",
            nargs="?",
            help="pid file, default: %(default)s, %(const)s if enabled",
            const=f"/run/{SERVICE_NAME}/{SERVICE_NAME}.pid"
        )

        parser.add_argument("-f", "--foreground",
            dest="foreground",
            action="store_true",
            help="stay in foreground (default: %(default)s)",
            default=False
        )

        parser.add_argument("--uid",
            dest="uid",
            help="run server on background with specific uid (default: %(default)s)",
            default=None
        )

        parser.add_argument("--gid",
            dest="gid",
            help="run server on backgroupd with specific gid (default: %(default)s)",
            default=None
        )

    parser.add_argument("--listen",
        dest="listen",
        type=int,
        help="listen port (default: %(default)s)",
        default=8118
    )

    parser.add_argument(
        dest="conffile",
        nargs='?',
        help="parse yaml configuration file (default: %(default)s)",
        default=f"{SERVICE_NAME}.yaml"
    )

    return parser.parse_args(args)


def set_logger(options):
    '''logger configuration'''
    options.verbosity = min(options.verbosity, 3)

    level = (
        logging.WARNING,
        logging.INFO,
        logging.DEBUG,
        logging.NOTSET,
        )[options.verbosity]

    logger = logging.getLogger()
    logger.setLevel(level)

    if options.logfile:
        filelogger = logging.handlers.RotatingFileHandler(options.logfile, maxBytes=10240, backupCount=4)
        filelogger.setFormatter(logging.Formatter('%(asctime)s %(levelname)s:%(name)s: %(message)s'))
        logger.addHandler(filelogger)

    if sys.platform == 'linux' and options.syslog:
        syslogger = logging.handlers.SysLogHandler(address = '/dev/log', facility = logging.handlers.SysLogHandler.LOG_LOCAL5)
        syslogger.setFormatter(logging.Formatter('%(name)s: %(message)s'))
        logger.addHandler(syslogger)

    if sys.platform == 'win32' or options.foreground:
        conslogger = logging.StreamHandler()
        if 'JOURNAL_STREAM' in os.environ:
            conslogger.setFormatter(logging.Formatter('%(levelname)s:%(name)s: %(message)s'))
        else:
            conslogger.setFormatter(logging.Formatter('%(asctime)s %(levelname)s:%(name)s: %(message)s'))
        logger.addHandler(conslogger)


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
    log = logging.getLogger('yaml_variables')
    class Struct:
        '''dictionary['key'] to dictionary.key convertion'''
        def __init__(self, entries):
            self.__dict__.update(entries)

    class SafeDict(dict):
        '''helper class for YamlEnv'''
        def __init__(self, arg:Optional[Dict]=None):
            if arg is None:
                super().__init__()
            else:
                super().__init__(arg)

        def __missing__(self, key):
            log.error('no binded variable: %s', key)
            return '{' + key + '}'

    class YamlEnv:
        '''format string using binded yaml sections contents'''
        global_env = SafeDict()
        def __init__(self, value:str):
            self.value = value
        def __repr__(self):
            return f"'{self.value.format_map(self.global_env)}'"
        def __str__(self):
            try:
                return self.value.format_map(self.global_env)
            except AttributeError:
                log.error('formatting error for: %s', self.value)
                return self.value
        def render(self, kwargs:Optional[dict]) -> str:
            """ render template string using yaml !bind data and kwargs """
            try:
                return self.value.format_map(SafeDict(kwargs)).format_map(self.global_env)
            except (ValueError, AttributeError):
                return self.value

    def var_constructor(loader: yaml.SafeLoader, node: yaml.ScalarNode):
        value = loader.construct_yaml_str(node)
        return YamlEnv(value)

    def var_representer(dumper:yaml.SafeDumper, data):
        return dumper.represent_scalar('!var', str(data))

    def include_constructor(loader: yaml.SafeLoader, node: yaml.ScalarNode):
        stream = cast(io.TextIOWrapper, loader.stream)
        _root = os.path.split(stream.name)[0] if loader.stream else '.'
        filename = os.path.join(_root, str(loader.construct_scalar(node)))
        try:
            with open(filename, 'r', encoding='utf-8') as file_object:
                return yaml.safe_load(file_object)
        except FileNotFoundError:
            log.error('included file not found: %s', filename)
            return {}

    def join_constructor(loader: yaml.SafeLoader, node: yaml.SequenceNode):
        seq = loader.construct_sequence(node)
        return ''.join([str(i) for i in seq])

    def bind_constructor(loader: yaml.SafeLoader, node: yaml.MappingNode):
        seq = loader.construct_mapping(node, deep=True)
        for key, value in seq.items():
            if isinstance(value, dict):
                YamlEnv.global_env[key] = Struct(value)
            else:
                YamlEnv.global_env[key] = value
        return None

    yaml.SafeLoader.add_constructor('!var', var_constructor)
    yaml.SafeLoader.add_implicit_resolver('!var', re.compile(r'.*{.*}.*'), None)
    yaml.SafeLoader.add_constructor('!include', include_constructor)
    yaml.SafeLoader.add_constructor('!join', join_constructor)
    yaml.SafeLoader.add_constructor('!bind', bind_constructor)
    yaml.SafeDumper.add_representer(YamlEnv, var_representer)

    if 'json' in globals():
        json = globals()['json']
        class JSONEncoder(json.JSONEncoder):
            """ YamlEnv json renderer """
            def __init__(self, local:Optional[Dict]=None):
                self._local = local
                super().__init__()
            def default(self, o):
                if isinstance(o, YamlEnv):
                    return o.render(self._local)
                return super().default(o)

        json._default_encoder = JSONEncoder()  # type: ignore
        json.JSONEncoder = JSONEncoder

    return YamlEnv.global_env


class Jumphost:
    '''jumphost.yaml parser'''
    def __init__(self, options: argparse.Namespace) -> None:
        self.log = logging.getLogger(__class__.__name__)
        self.options = options
        self.proxylist: dict[int, asyncio.Server] = {}
        self.protocol_factory: dict[int, Any] = {}
        self.loop: asyncio.AbstractEventLoop
        self._pac: str = ''
        self.mtime: float = 0.0
        self.keepass = None
        self.env = yaml_variables()

    def _loadconfig(self, options: argparse.Namespace) -> dict[int, list[proxy.BaseClient]]:
        self.log.info('reloading config %s', options.conffile)

        jumphosts: dict[str, dict[str, Any]] = {}
        servers: dict[int, list[proxy.BaseClient]] = {}

        if os.path.isfile(options.conffile):
            self.mtime = os.path.getmtime(options.conffile)
            with open(options.conffile, encoding='utf-8') as stream:
                try:
                    jumphosts = yaml.safe_load(stream)
                    imports = [filename for filemask in jumphosts.pop('import', []) for filename in glob.glob(os.path.join(os.path.dirname(options.conffile), filemask))]
                    for filename in imports:
                        self.log.info('import config: %s', filename)
                        jumphosts.update(yaml.safe_load(open(filename, encoding='utf-8')))
                except yaml.YAMLError as ex:
                    self.log.error("configuration file %s parse error: %s", options.conffile, ex)
        else:
            self.log.warning("can't find configuration file %s, using default config", options.conffile)
            jumphosts = {'direct': {}}

        if 'keepass' in jumphosts:
            cfg = jumphosts.pop('keepass')
            if 'filename' in cfg:
                cfg['filename'] = os.path.expanduser(cfg['filename'])
            if 'keyfile' in cfg:
                cfg['keyfile'] = os.path.expanduser(cfg['keyfile'])

            group = cfg.pop('group', 'jumphost')

            if self.keepass is None or \
                self.keepass.filename != cfg.get('filename') or \
                self.keepass.keyfile != cfg.get('keyfile'):
                self.keepass = pykeepass.PyKeePass(**cfg)
            else:
                self.keepass.reload()

            keepass_group = self.keepass.find_groups(name=group, first=True)
            if isinstance(keepass_group, pykeepass.group.Group):
                for entry in keepass_group.entries:
                    self.env[entry.title] = entry

        for jumpname, jumpconf in jumphosts.items():
            if not isinstance(jumpconf, dict):
                continue

            if isinstance(jumpconf.setdefault('net', []), str):
                jumpconf['net'] = [jumpconf['net']]
            if isinstance(jumpconf.setdefault('proxy', []), str):
                jumpconf['proxy'] = [jumpconf['proxy']]

            connection = proxy.BaseClient.connection(jumpconf['proxy'])
            connection.rule(jumpconf['net'])
            connection.hosts(jumpconf.get('hosts'))
            self.log.debug('%s=%s', jumpname, connection)

            servers.setdefault(jumpconf.get('listen', options.listen), []).append(connection)

        return servers

    async def reload(self):
        '''start/reload proxy factory and generate pac file contents'''
        def dict_compare(d1_dict: dict[Any,Any], d2_dict: dict[Any,Any]):
            d1_keys = set(d1_dict.keys())
            d2_keys = set(d2_dict.keys())
            shared_keys = d1_keys.intersection(d2_keys)
            added = d1_keys - d2_keys
            removed = d2_keys - d1_keys
            return added, removed, shared_keys

        proxy_factory = self._loadconfig(self.options)
        added, removed, shared = dict_compare(proxy_factory, self.proxylist)

        for listen in removed:
            self.protocol_factory.pop(listen)
            proxyserver = self.proxylist.pop(listen)
            proxyserver.close()

        for listen in added:
            self.protocol_factory[listen] = partial(proxy.ProxyServer, rserver=proxy_factory[listen])
            self.proxylist[listen] = await self.loop.create_server(
                    self.protocol_factory[listen],
                    port=listen, reuse_address=True, start_serving=True
                )

        for listen in shared:
            self.protocol_factory[listen].keywords['rserver'] = proxy_factory[listen]

        #generate pac file
        pacdict = {}
        for connection in proxy_factory[self.options.listen]:
            if  isinstance(connection, (proxy.DirectClient, proxy.Socks4Client, proxy.Socks5Client)) and  \
                isinstance(connection.jumphost, asyncio.AbstractEventLoop) and \
                not connection.hosts:
                assert connection.options.scheme
                proxyurl = f'{connection.options.scheme.upper()} {connection.options.hostid}'
            else:
                proxyurl = f'SOCKS5 localhost:{self.options.listen}'

            pacdict.setdefault(proxyurl, proxy.MatchList()).extend(connection.matchlist)

        paclist = (f'  if({v})\n  {{return "{k}";}}' for k, v in pacdict.items())
        self._pac = 'function FindProxyForURL (url, host) {{\n{0}\n  return "DIRECT";\n}}\n'.format('\n'.join(paclist))

    async def http(self, reader, writer):
        '''http get response pac contents'''
        if os.path.isfile(self.options.conffile):
            await self.reload()

        body = self._pac.encode()
        response = [
            b'HTTP/1.1 200 OK',
            b'Content-Type: text/plain; charset=utf-8',
            b'Content-Length: %d' % len(body),
            b'',
            body,
        ]
        writer.write(b'\r\n'.join(response))
        await writer.drain()
        writer.close()


def daemonize():
    '''start service as daemon'''
    options = getoptions()
    set_logger(options)
    jumphost = Jumphost(options)
    if sys.platform == 'linux':
        setproctitle.setproctitle(SERVICE_NAME)
        with daemon.DaemonContext(
            pidfile = daemon.pidfile.PIDLockFile(options.pid) if options.pid else None,
            signal_map = {signal.SIGTERM: lambda signum, stack_frame: sys.exit(0)},
            detach_process = not options.foreground,
            stdout = sys.stdout if options.foreground else None,
            stderr = sys.stderr if options.foreground else None,
            uid = pwd.getpwnam(options.uid).pw_uid if options.uid else None,
            gid = grp.getgrnam(options.gid).gr_gid if options.gid else None,
            files_preserve = [3] if 'LISTEN_FDNAMES' in os.environ else None,
            working_directory = os.path.dirname(os.path.abspath(options.conffile)),
            ):
            options.conffile = os.path.basename(options.conffile)
            if options.uid:
                os.environ['HOME'] = os.path.expanduser(f"~{options.uid}")
            main(jumphost)
    else:
        main(jumphost)


def main(jumphost: Jumphost):
    '''main'''
    logging.getLogger('asyncssh').setLevel(logging.WARN)
    logging.getLogger('pykeepass').setLevel(logging.WARN)
    logging.info("starting %s version %s", SERVICE_NAME, PKG_VERSION)

    if sys.platform == 'linux':
        uvloop.install()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def exception_handler(_, context):
        logging.exception('asyncloop exception:', exc_info=context.get('exception'))

    loop.set_exception_handler(exception_handler)
    jumphost.loop = loop
    loop.run_until_complete(jumphost.reload())

    loop.run_until_complete(asyncio.start_server(
                    jumphost.http,
                    port=8110, reuse_address=True, start_serving=True
                ))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        logging.info('main exit')
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()


if __name__ == '__main__':
    daemonize()
