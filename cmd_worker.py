from pylc.models.livegateapi import Command
from utils import json_response, validate_json_obj
from const import SUCCESS, HTTP_OK, ROUTER_SCRIPT
from logger import log
from task import cmd_waiting_queues_put, cmd_response_get, router_hash, \
    read_response_handle, PseudoGeventQueue


@validate_json_obj(obj_cls=Command)
def put_cmd(cmd, router_id):
    log.debug('router_id: %r, command: %r' % (router_id, cmd.to_native()))

    key = ('exec-cmd', cmd.command, str(router_id))
    message = []

    args = [
        ROUTER_SCRIPT,
        cmd.command,
        str(router_id),
        cmd.if_type,
        str(cmd.if_index),
        cmd.source,
        cmd.target,
        '%.3f' % (cmd.interval / 1000.0),
    ]
    message.append(args)

    ret_queue = PseudoGeventQueue()
    cmd_waiting_queues_put(router_id, router_hash,
                           key, message, ret_queue)
    ret_list = []
    err = cmd_response_get(ret_queue, read_response_handle(ret_list))
    if err or not ret_list:
        return json_response(
            data={'OUTPUT': ''}, status=SUCCESS), HTTP_OK
    else:
        return json_response(
            data={'OUTPUT': ret_list[0]}, status=SUCCESS), HTTP_OK
