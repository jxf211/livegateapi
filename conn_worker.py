from pylc.models.livegateapi import Conntrack
from utils import json_response, validate_json_obj
from const import SUCCESS, HTTP_OK, SERVER_ERROR, \
    HTTP_INTERNAL_SERVER_ERROR, ROUTER_SCRIPT
from logger import log
from task import cmd_waiting_queues_put, cmd_response_get, router_hash, \
    read_response_handle, PseudoGeventQueue


@validate_json_obj(obj_cls=Conntrack)
def create_conn_limit(conn, router_id):
    key = ('create', 'conn', str(router_id))
    args = [
        ROUTER_SCRIPT,
        'add', 'conntrack',
        '%d' % router_id,
        '%d' % conn.conn_max,
        '%d' % conn.new_conn_per_sec,
    ]

    ret_queue = PseudoGeventQueue()
    cmd_waiting_queues_put(router_id,
                           router_hash,
                           key,
                           args,
                           ret_queue)
    output = cmd_response_get(ret_queue)
    if output:
        log.error('router %d: %s' % (router_id, output))
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK


def read_conn_limit(router_id):
    key = ('read', 'conn', str(router_id))
    args = [
        ROUTER_SCRIPT,
        'get', 'conntrack',
        '%d' % router_id
    ]

    ret_queue = PseudoGeventQueue()
    cmd_waiting_queues_put(router_id,
                           router_hash,
                           key,
                           args,
                           ret_queue)
    ret_list = []
    output = cmd_response_get(ret_queue, read_response_handle(ret_list))
    if output:
        log.error('router %d: %s' % (router_id, output))
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(
        status=SUCCESS, data={"RESULT": ret_list[0]}), HTTP_OK


@validate_json_obj(obj_cls=Conntrack)
def update_conn_limit(conn, router_id):
    key = ('update', 'conn', str(router_id))
    args = [
        ROUTER_SCRIPT,
        'add', 'conntrack',
        '%d' % router_id,
        '%d' % conn.conn_max,
        '%d' % conn.new_conn_per_sec,
    ]

    ret_queue = PseudoGeventQueue()
    cmd_waiting_queues_put(router_id,
                           router_hash,
                           key,
                           args,
                           ret_queue)
    output = cmd_response_get(ret_queue)
    if output:
        log.error('router %d: %s' % (router_id, output))
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK


def delete_conn_limit(router_id):
    key = ('delete', 'conn', str(router_id))
    args = [
        ROUTER_SCRIPT,
        'delete', 'conntrack',
        '%d' % router_id
    ]

    ret_queue = PseudoGeventQueue()
    cmd_waiting_queues_put(router_id,
                           router_hash,
                           key,
                           args,
                           ret_queue)
    output = cmd_response_get(ret_queue)
    if output:
        log.error('router %d: %s' % (router_id, output))
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK
