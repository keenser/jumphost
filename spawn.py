#!/usr/bin/env python3
#
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
#
'''
run shell commands
'''
import os
import asyncio
import logging
from typing import Any
import pexpect
try:
    from securid.stoken import StokenFile
except ModuleNotFoundError:
    pass

class Spawn:
    '''run shell command in loop'''
    def __init__(self, identificator: str, *args: Any):
        self.identificator = identificator
        self.log = logging.getLogger(identificator)
        self.connection = None
        loop = asyncio.get_event_loop()
        self.task = loop.create_task(self.spawn(*args))

    async def callback(self, *args: Any) -> pexpect.spawn:
        '''create connection  using pexpect.spawn(cmd)'''
        raise NotImplementedError

    async def close(self):
        '''close shell connection'''
        if self.connection:
            self.connection.sendcontrol('c')
            await self.connection.expect([pexpect.TIMEOUT, pexpect.EOF], async_=True)
            self.connection.close()

    async def spawn(self, *args: Any) -> None:
        '''spawn shell command ifinity loop'''
        timeings = 1
        while True:
            try:
                try:
                    self.connection = await self.callback(*args)
                    self.log.info('logged in')
                    timeings = 1
                    await self.connection.expect_exact(pexpect.EOF, async_=True, timeout=None)  # type: ignore
                except (pexpect.exceptions.TIMEOUT, pexpect.exceptions.EOF) as ex:
                    if timeings < 128:
                        timeings *= 2
                    self.log.error('catch pexpect exception %s', ex.__class__.__name__)
                if self.connection:
                    self.connection.close()
                self.log.info('reconnect after %d sec', timeings)
                await asyncio.sleep(timeings)
            except asyncio.CancelledError:
                break
            except Exception:
                self.log.exception('spawn')

        if self.connection and self.connection.isalive():
            self.log.info('send exit')
            try:
                await self.close()
            except Exception:
                self.log.exception('spawn exit')
        self.log.info('exited')


class Ssh(Spawn):
    '''start ssh if we are inside NC domain'''
    SSH = 'ssh -o ServerAliveInterval=60 -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes'
    def __init__(self, identificator: str, cmd: str, *passwords: str):
        super().__init__(identificator, cmd, *passwords)

    async def close(self):
        if self.connection and self.connection.isalive():
            self.connection.sendcontrol('c')
            await self.connection.expect_exact(['$', '#', pexpect.TIMEOUT, pexpect.EOF], async_=True)
            if self.connection.isalive():
                self.connection.sendline('exit')
                await self.connection.expect_exact([pexpect.TIMEOUT, pexpect.EOF], async_=True)
            self.connection.close()

    # pylint: disable=arguments-differ
    async def callback(self, cmd: str, *passwords: str):
        self.log.info('ssh %s', cmd)
        if 'microsoft' in os.uname().release and os.access('/mnt/c/Windows/System32/ipconfig.exe', os.X_OK):
            ssh_string = f'/bin/bash -c "if [ `/mnt/c/Windows/System32/ipconfig.exe | grep -c corp` -eq 1 ] ; then {self.SSH} {cmd}; fi"'
        else:
            ssh_string = f'/bin/bash -c "ping -c 1 -W 1 10.10.1.3; if [ $? -eq 0 ] ; then {self.SSH} {cmd}; fi"'

        connection = pexpect.spawn(ssh_string)
        for password in passwords:
            ret = await connection.expect_exact(['(yes/no)?', 'assword:'], async_=True)
            self.log.debug('%s%s', connection.before, connection.after)
            if ret == 0:
                connection.sendline('yes')
                await connection.expect_exact('assword:', async_=True)
            self.log.info('send password %s', password)
            connection.sendline(password)
        await connection.expect_exact(['$', '#'], async_=True)
        if connection.before and connection.after:
            self.log.debug('%s%s', connection.before.decode(), connection.after.decode())
        return connection


class Forti(Spawn):
    '''start openfortivpn with 2factor authorization'''
    def __init__(self, identificator: str, cmd: str, config: dict[str, str], env: dict[str, str]):
        super().__init__(identificator, cmd, config, env)
        try:
            stoken = StokenFile()
            self.token = stoken.get_token()
        except (NameError, FileNotFoundError):
            self.token = None

    def forticonfig(self, config: dict[str, str], env: dict[str, str]):
        '''dynamically create openfortivpn config file'''
        configfile = f'/tmp/{self.identificator}'
        with open(os.open(configfile, os.O_CREAT | os.O_WRONLY, 0o600), 'w') as file_object:
            filelines = []
            for key, value in config.items():
                if isinstance(value, list):
                    for valueitem in value:
                        filelines.append(f'{key} = {valueitem}')
                else:
                    filelines.append(f'{key} = {value}')
            filecontent = '\n'.join(filelines).format(**env)
            file_object.write(filecontent)
        return configfile

    # pylint: disable=arguments-differ
    async def callback(self, cmd: str, config: dict[str, str], env: dict[str, str]):
        self.log.info('forti %s', cmd)
        if self.token:
            env['token'] = self.token.now()

        conffile = None
        try:
            conffile = self.forticonfig(config, env)
            connection = pexpect.spawn(cmd.format(config=conffile))
            await connection.expect_exact('Connected to gateway.', async_=True, timeout=None)  # type: ignore
            os.unlink(conffile)
            await connection.expect_exact('Tunnel is up and running', async_=True, timeout=None)  # type: ignore
            if connection.before and connection.after:
                self.log.debug('%s%s', connection.before.decode() if connection.before != pexpect.EOF else '', connection.after.decode() if connection.after != pexpect.EOF else '')
            return connection
        finally:
            if conffile and os.path.isfile(conffile):
                os.unlink(conffile)


class Proc(Spawn):
    '''start any simple shell command'''
    # pylint: disable=arguments-differ
    async def callback(self, cmd: str):
        self.log.info('proc %s', cmd)
        connection = pexpect.spawn(cmd)
        return connection
