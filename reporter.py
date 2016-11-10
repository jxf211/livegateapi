import time
import requests
import threading
import lg_sysconfig

from logger import log
from const import CALLBACK_TO_LCC_TALKER, CALLBACK_SYSTEM_BOOT, \
    CALLBACK_RETRY, HTTP_OK, SYSTEM_BOOTUP_WINDOW


reported_ctrls = {}
bootup_time = time.time()


def run_report_bootup(ctrl_ip):
    if ctrl_ip in reported_ctrls and reported_ctrls[ctrl_ip] == 0:
        return

    r = requests.post(
        (CALLBACK_TO_LCC_TALKER % ctrl_ip) + CALLBACK_SYSTEM_BOOT
    )
    if r.status_code != HTTP_OK:
        log.error('Report system bootup to %s failed (%d: %s), '
                  'retry after 60 seconds', ctrl_ip, r.status_code, r.text)
        threading.Timer(
            CALLBACK_RETRY, run_report_bootup, [ctrl_ip]).start()
        reported_ctrls[ctrl_ip] = CALLBACK_RETRY
    else:
        log.info('Report system bootup to %s succeed', ctrl_ip)
        reported_ctrls[ctrl_ip] = 0
    for k, v in reported_ctrls.items():
        log.debug('Bootup report recored: %s next try %d' % (k, v))


def report_bootup(ctrl_ip):
    if not lg_sysconfig.is_system_bootup:
        return
    if ctrl_ip in reported_ctrls:
        return
    if time.time() - bootup_time > SYSTEM_BOOTUP_WINDOW:
        log.info('Ignore report request to %s since system is running more '
                 'than %d seconds (%d).', ctrl_ip, SYSTEM_BOOTUP_WINDOW,
                 time.time() - bootup_time)
        reported_ctrls[ctrl_ip] = 0
        return
    threading.Timer(0, run_report_bootup, [ctrl_ip]).start()
