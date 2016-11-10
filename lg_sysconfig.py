import sys
import time

from logger import log
from const import ROUTER_SCRIPT, SYSCONF_SCRIPT, SYSTEM_BOOTUP_WINDOW
from utils import call_system_sh


is_system_bootup = False


def init_system(force=False):
    if not force:
        args = [
            SYSCONF_SCRIPT,
            'CHECK_SYSTEM_BOOTUP',
        ]
        rc, output = call_system_sh(args)
        log.info('System bootup %ss ago', output)
        if rc == 0 and int(output) > SYSTEM_BOOTUP_WINDOW:
            log.info('Skip init_system.')
            return

    global is_system_bootup
    is_system_bootup = True
    log.info('Init system now, clear all routers ...')

    args = [
        ROUTER_SCRIPT,
        'delete', 'all_routers',
    ]
    rc, output = call_system_sh(args)
    if rc != 0:
        log.error('Init system failed, exit after 10 seconds.')
        time.sleep(10)
        sys.exit(-1)
