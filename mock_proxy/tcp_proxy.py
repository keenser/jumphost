#!/usr/bin/env python3
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import logging
import asyncio
import ssl
import os
import sys
import socket

host = sys.argv[1]
port = int(sys.argv[2])

class StreamProtocol(asyncio.Protocol):
    '''Simple connection protocol between server and client connection'''
    def __init__(self, peer_transport, queue:asyncio.Queue):
        self.loop = asyncio.get_running_loop()
        self._transport = None
        self.queue = queue
        self._peer_transport = peer_transport

    def data_received(self, data):
        logging.info('server data: %s', data)
        self._peer_transport.write(data)

    def connection_lost(self, exc):
        self._peer_transport.close()

    def connection_made(self, transport:asyncio.Transport):
        local_side = '%s:%d' % transport.get_extra_info('sockname')[:2]
        remote_side = '%s:%d' % transport.get_extra_info('peername')[:2]
        sock = transport.get_extra_info('socket')
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 10)
        logging.info('server connection made %s %s', local_side, remote_side)
        self._transport = transport
        for data in self.queue.get_nowait():
            self._transport.write(data)


class ServerProtocol(asyncio.Protocol):
    '''Simple connection protocol between server and client connection'''
    def __init__(self):
        super().__init__()
        self.loop = asyncio.get_running_loop()
        self.queue = asyncio.Queue()
        self._transport = None
        self._peer_transport = None

    def data_received(self, data):
        logging.info('client data: %s', data)
        if self._peer_transport:
            self._peer_transport.write(data)
        else:
            self.queue.put_nowait((data,))

    def connection_lost(self, exc):
        if self._peer_transport:
            self._peer_transport.close()

    def connection_made(self, transport:asyncio.Transport):
        local_side = '%s:%d' % transport.get_extra_info('sockname')[:2]
        remote_side = '%s:%d' % transport.get_extra_info('peername')[:2]
        logging.info('client connection made %s %s', remote_side, local_side)
        self._transport = transport
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        task = self.loop.create_task(
            self.loop.create_connection(lambda: StreamProtocol(transport, self.queue), host, port, ssl=ssl_context)
        )
        def connect_callback(result: asyncio.Task[tuple[asyncio.BaseTransport, StreamProtocol]]):
            if result.exception():
                if self._transport:
                    self._transport.close()
            (self._peer_transport, _) = result.result()

        task.add_done_callback(connect_callback)


def main():
    """ entry point """
    logging.addLevelName(logging.DEBUG - 5, 'TRACE')
    logging.basicConfig(format='%(asctime)s %(levelname)s:%(name)s: %(message)s')
    logging.getLogger().setLevel(logging.getLevelName(os.environ.get('LOG_LEVEL', 'INFO')))

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    ssl_config = {
        "certfile": "/etc/ssl/certs/ssl-cert-snakeoil.pem",
        "keyfile": "/etc/ssl/private/ssl-cert-snakeoil.key"
    }
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(**ssl_config)
    srv = loop.run_until_complete(loop.create_server(ServerProtocol, port=8543, ssl=ssl_context))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
        loop.close()

if __name__ == '__main__':
    main()
