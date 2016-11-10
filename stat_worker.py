from pylc.models.livegateapi import NspStat
import logging
import time
import copy
import threading
import simplejson as json
from utils import call_system_sh, json_response
from const import SUCCESS, HTTP_OK, NSP_STAT_SCRIPT, SERVER_ERROR, \
    HTTP_INTERNAL_SERVER_ERROR


log = logging.getLogger(__name__)
REALTIME_CACHE_EXPIRE = 5
GENERAL_CACHE_EXPIRE = 60

nsp_stat_cache_lock = threading.Lock()
sys_cmd_lock = threading.Lock()
nsp_stat_cache = [None, None]  # [is_realtime] = NspStatCacheNode()
nsp_stat_flush_time = [None, None]  # [is_realtime] = int


class NspStatCacheNode:
    def __init__(self, now, hit_time, nsp_stat):
        self.load_time = now
        self.hit_time = hit_time
        self.nsp_stat = nsp_stat


def nsp_stat_cache_flush(delay, realtime, hit_time):
    threading.Timer(delay, get_nsp_stat, [realtime, hit_time]).start()


def nsp_stat(realtime=False):
    cache_index = 1 if realtime else 0
    cache_expire = REALTIME_CACHE_EXPIRE if realtime else GENERAL_CACHE_EXPIRE

    now = time.time()
    prev_hit = 0
    json_resp = None

    with nsp_stat_cache_lock:
        if nsp_stat_cache[cache_index] is not None:
            prev_hit = nsp_stat_cache[cache_index].hit_time
            nsp_stat_cache[cache_index].hit_time = now
            if now - nsp_stat_cache[cache_index].load_time < cache_expire:
                json_resp = copy.deepcopy(nsp_stat_cache[cache_index].nsp_stat)

    if prev_hit != 0 and now - prev_hit >= 3:  # ignore benchmark test request
        flush_time = now + now - prev_hit - 2
        if nsp_stat_flush_time[cache_index] < flush_time:
            nsp_stat_flush_time[cache_index] = flush_time
            nsp_stat_cache_flush(now - prev_hit - 2, realtime, now)

    if json_resp is not None:
        return json_resp, HTTP_OK
    return get_nsp_stat(realtime, now)


def get_nsp_stat(realtime, hit_time):
    cache_index = 1 if realtime is True else 0
    now = time.time()

    args = [
        NSP_STAT_SCRIPT,
        'realtime' if realtime else 'general'
    ]
    with sys_cmd_lock:
        rc, output = call_system_sh(args)
        if rc != 0:
            return json_response(
                status=SERVER_ERROR, description=output
            ), HTTP_INTERNAL_SERVER_ERROR

    try:
        nsp_stat = NspStat(json.loads(output))
        nsp_stat.validate()
        json_resp = json_response(
            status=SUCCESS, data=nsp_stat.to_primitive(), type="NSP_STAT")
    except Exception as e:
        log.error(e)
        log.error(output)
        return json_response(
            status=SERVER_ERROR, description=str(e)
        ), HTTP_INTERNAL_SERVER_ERROR

    with nsp_stat_cache_lock:
        nsp_stat_cache[cache_index] = NspStatCacheNode(
            now, hit_time, json_resp)
    return json_resp, HTTP_OK
