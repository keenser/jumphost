#!/usr/bin/env python3
#
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
#
import asyncio
from functools import partial
import logging
import requests
import proxy

class RadixNode(dict):
    def __init__(self):
        super().__init__()
        self.hostname = set()
    def __iadd__(self, key):
        if isinstance(key, str):
            key = key.split('.')
        if len(key) > 1:
            self.setdefault(key[-1], RadixNode()).__iadd__(key[:-1])
            if key[-2] == '*':
                self.hostname.add(key[-1])
        else:
            self.hostname.add(key[0])
        return self
    def __repr__(self):
        ret = []
        if self.hostname:
            ret.append(repr(self.hostname))
        if self:
            ret.append(super().__repr__())
        return ' '.join(ret)
    def __eq__(self, key):
        if isinstance(key, str):
            key = key.split('.')
        if '*' in self.hostname:
            return True
        elif len(key) > 1:
            return key[-1] in self and self[key[-1]] == key[:-1]
        else:
            return key[0] in self.hostname

def main():
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger('asyncssh').setLevel(logging.WARN)

    tree = RadixNode()

    ret = requests.get('https://reestr.rublacklist.net/api/v2/domains/json', timeout=60)
    for domain in ret.json():
        tree += domain

    connection = proxy.BaseClient.connection(['ssh://debian@localhost'])
    connection.matchlist = tree

    loop = asyncio.get_event_loop()
    loop.run_until_complete(loop.create_server(
                    partial(proxy.ProxyServer, rserver=[connection]),
                    port=8110, reuse_address=True, start_serving=True
                )
    )

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))

        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()

if __name__ == '__main__':
    main()
