#
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
#
# pip install asyncssh aiosocks pyyaml infi.systray

from infi.systray import SysTrayIcon
import jumphost
import signal
import asyncio
import os

def systray(jmp: jumphost.Jumphost):
    def reload(systray):
        asyncio.run_coroutine_threadsafe(jmp.reload(), jmp.loop)

    def openconfig(systray):
         os.startfile(jmp.options.conffile)

    def bye(sysTrayIcon):
        signal.raise_signal(signal.SIGINT)

    menu_options = (
        ("Reload config", None, reload),
        ("Open config", None, openconfig),
    )
    systray = SysTrayIcon("icon.ico", jumphost.SERVICE_NAME, menu_options, on_quit=bye)
    systray.start()


def main():
    options = jumphost.getoptions(['-vv', '--log', 'log/jumphost.log'])
    jumphost.set_logger(options)
    jmp = jumphost.Jumphost(options)
    systray(jmp)
    jumphost.main(jmp)


if __name__ == '__main__':
    main()
