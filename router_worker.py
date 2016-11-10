import simplejson as json
from pylc.models.livegateapi import Router, Wan, Lan
from utils import json_response, validate_json_obj
from const import SUCCESS, HTTP_OK, ROUTER_SCRIPT, SERVER_ERROR, \
    HTTP_INTERNAL_SERVER_ERROR, PARAMETER_ILLEGAL, HTTP_BAD_REQUEST, \
    VIF_ATTACH
from logger import log
from task import cmd_waiting_queues_put, cmd_response_get, router_hash, \
    read_response_handle, PseudoGeventQueue

# Router


@validate_json_obj(obj_cls=Router)
def create_router(router):
    return create_router_worker(router)


def create_router_worker(router):
    log.debug('router: %r' % router.to_native())

    key = ('create', 'router', str(router.router_id))
    message_del = get_delete_router_args(router.router_id)
    message_create = []

    for wan in router.wans:
        if wan.state == VIF_ATTACH:
            args = [
                ROUTER_SCRIPT,
                'add', 'wan',
                str(router.router_id),
                str(wan.if_index),
                str(wan.isp),
                wan.gateway,
                wan.mac,
                str(wan.vlantag),
                str(wan.qos.min_bandwidth),
                str(wan.qos.max_bandwidth),
                str(wan.broadcast_qos.min_bandwidth),
                str(wan.broadcast_qos.max_bandwidth),
            ]
            for ip in wan.ips:
                args.append(ip.address)
                args.append(ip.netmask)
        else:
            continue
        message_create.append(args)

    for lan in router.lans:
        if lan.state == VIF_ATTACH:
            args = [
                ROUTER_SCRIPT,
                'add', 'lan',
                str(router.router_id),
                str(lan.if_index),
                lan.mac,
                str(lan.vlantag),
                str(lan.qos.min_bandwidth),
                str(lan.qos.max_bandwidth),
            ]
            for ip in lan.ips:
                args.append(ip.address)
                args.append(ip.netmask)
        else:
            continue
        message_create.append(args)

    args = [
        ROUTER_SCRIPT,
        'add', 'conntrack',
        str(router.router_id),
        str(router.conn_limit.conn_max),
        str(router.conn_limit.new_conn_per_sec),
    ]
    message_create.append(args)

    message = message_del + message_create

    ret_queue = PseudoGeventQueue()
    cmd_waiting_queues_put(router.router_id, router_hash,
                           key, message, ret_queue)
    output = cmd_response_get(ret_queue)
    if output:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR
    return json_response(status=SUCCESS), HTTP_OK


def read_router(router_id):
    log.debug('router_id: %r' % router_id)
    key = ('read', 'router', str(router_id))
    ret_queue = PseudoGeventQueue()
    args = [
        ROUTER_SCRIPT,
        'get', 'router',
        str(router_id),
    ]
    cmd_waiting_queues_put(router_id,
                           router_hash,
                           key,
                           args,
                           ret_queue)
    ret_list = []
    output = cmd_response_get(ret_queue, read_response_handle(ret_list))
    if output:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    try:
        router = Router(json.loads(ret_list[0]))
        router.validate()
        return json_response(
            status=SUCCESS, data=router.to_primitive(), type="ROUTER"), HTTP_OK
    except Exception, e:
        log.debug(e)
        log.debug(output)
        return json_response(
            status=SERVER_ERROR, description=str(e)
        ), HTTP_INTERNAL_SERVER_ERROR


@validate_json_obj(obj_cls=Router)
def update_router(router, router_id):
    if router.router_id != router_id:
        return json_response(
            status=PARAMETER_ILLEGAL, description='Inconsistent ROUTER ID'
        ), HTTP_BAD_REQUEST
    return create_router_worker(router)


def get_delete_router_args(router_id, remove_vport=False):
    message = []
    args = [
        ROUTER_SCRIPT,
        'delete', 'router',
        str(router_id),
        '1' if remove_vport else '0'
    ]
    message.append(args)
    args = [
        ROUTER_SCRIPT,
        'delete', 'conntrack',
        str(router_id)
    ]
    message.append(args)
    return message


def delete_router(router_id, remove_vport=False):
    key = ('delete', 'router', str(router_id))
    ret_queue = PseudoGeventQueue()
    cmd_waiting_queues_put(router_id,
                           router_hash,
                           key,
                           get_delete_router_args(router_id, remove_vport),
                           ret_queue)
    output = cmd_response_get(ret_queue)
    if output:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK


# Wan


@validate_json_obj(obj_cls=Wan)
def create_wan(wan, router_id):
    return create_wan_worker(wan, router_id)


def create_wan_worker(wan, router_id):
    log.debug('router_id: %d, wan: %r' % (router_id, wan.to_native()))

    key = ('create', 'router-wan', str(router_id), str(wan.if_index))
    message = []
    message.append(get_delete_wan_args(router_id, wan.if_index))

    args = [
        ROUTER_SCRIPT,
        'add', 'wan',
        str(router_id),
        str(wan.if_index),
        str(wan.isp),
        wan.gateway,
        wan.mac,
        str(wan.vlantag),
        str(wan.qos.min_bandwidth),
        str(wan.qos.max_bandwidth),
        str(wan.broadcast_qos.min_bandwidth),
        str(wan.broadcast_qos.max_bandwidth),
    ]
    for ip in wan.ips:
        args.append(ip.address)
        args.append(ip.netmask)
    message.append(args)

    ret_queue = PseudoGeventQueue()
    cmd_waiting_queues_put(router_id,
                           router_hash,
                           key,
                           message,
                           ret_queue)

    output = cmd_response_get(ret_queue)
    if output:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK


def read_wan(router_id, if_index):
    log.debug('wan_id: %d-%r' % (router_id, if_index))
    key = ('read', 'router-wan', str(router_id), str(if_index))
    ret_queue = PseudoGeventQueue()
    args = [
        ROUTER_SCRIPT,
        'get', 'wan',
        str(router_id),
        str(if_index),
    ]
    cmd_waiting_queues_put(router_id,
                           router_hash,
                           key,
                           args,
                           ret_queue)
    ret_list = []
    output = cmd_response_get(ret_queue, read_response_handle(ret_list))
    if output:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    try:
        wan = Wan(json.loads(ret_list[0]))
        wan.validate()
        return json_response(
            status=SUCCESS, data=wan.to_primitive(), type="WAN"), HTTP_OK
    except Exception, e:
        log.debug(e)
        log.debug(output)
        return json_response(
            status=SERVER_ERROR, description=str(e)
        ), HTTP_INTERNAL_SERVER_ERROR


@validate_json_obj(obj_cls=Wan)
def update_wan(wan, router_id, if_index):
    if wan.if_index != if_index:
        return json_response(
            status=PARAMETER_ILLEGAL, description='Inconsistent IF_INDEX'
        ), HTTP_BAD_REQUEST
    return create_wan_worker(wan, router_id)


def get_delete_wan_args(router_id, if_index):
    args = [
        ROUTER_SCRIPT,
        'delete', 'wan',
        str(router_id),
        str(if_index),
    ]
    return args


def delete_wan(router_id, if_index, ret_queue=None):
    key = ('delete', 'router-wan', str(router_id), str(if_index))
    ret_queue = PseudoGeventQueue()
    cmd_waiting_queues_put(router_id,
                           router_hash,
                           key,
                           get_delete_wan_args(router_id, if_index),
                           ret_queue)
    output = cmd_response_get(ret_queue)
    if output:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK


# Lan


@validate_json_obj(obj_cls=Lan)
def create_lan(lan, router_id):
    return create_lan_worker(lan, router_id)


def create_lan_worker(lan, router_id):
    log.debug('router_id: %d, lan: %r' % (router_id, lan.to_native()))

    key = ('create', 'router-lan', str(router_id), str(lan.if_index))
    message = []
    message.append(get_delete_lan_args(router_id, lan.if_index))

    args = [
        ROUTER_SCRIPT,
        'add', 'lan',
        str(router_id),
        str(lan.if_index),
        lan.mac,
        str(lan.vlantag),
        str(lan.qos.min_bandwidth),
        str(lan.qos.max_bandwidth),
    ]
    for ip in lan.ips:
        args.append(ip.address)
        args.append(ip.netmask)
    message.append(args)

    ret_queue = PseudoGeventQueue()
    cmd_waiting_queues_put(router_id,
                           router_hash,
                           key,
                           message,
                           ret_queue)

    output = cmd_response_get(ret_queue)
    if output:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK


def read_lan(router_id, if_index):
    key = ('read', 'router-lan', str(router_id), str(if_index))
    ret_queue = PseudoGeventQueue()
    args = [
        ROUTER_SCRIPT,
        'get', 'lan',
        str(router_id),
        str(if_index),
    ]
    cmd_waiting_queues_put(router_id,
                           router_hash,
                           key,
                           args,
                           ret_queue)
    ret_list = []
    output = cmd_response_get(ret_queue, read_response_handle(ret_list))
    if output:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    try:
        lan = Lan(json.loads(ret_list[0]))
        lan.validate()
        return json_response(
            status=SUCCESS, data=lan.to_primitive(), type="LAN"), HTTP_OK
    except Exception, e:
        log.debug(e)
        log.debug(output)
        return json_response(
            status=SERVER_ERROR, description=str(e)
        ), HTTP_INTERNAL_SERVER_ERROR


@validate_json_obj(obj_cls=Lan)
def update_lan(lan, router_id, if_index):
    if lan.if_index != if_index:
        return json_response(
            status=PARAMETER_ILLEGAL, description='Inconsistent IF_INDEX'
        ), HTTP_BAD_REQUEST
    return create_lan_worker(lan, router_id)


def get_delete_lan_args(router_id, if_index):
    args = [
        ROUTER_SCRIPT,
        'delete', 'lan',
        str(router_id),
        str(if_index),
    ]
    return args


def delete_lan(router_id, if_index, ret_queue=None):
    key = ('delete', 'router-lan', str(router_id), str(if_index))
    ret_queue = PseudoGeventQueue()
    cmd_waiting_queues_put(router_id,
                           router_hash,
                           key,
                           get_delete_lan_args(router_id, if_index),
                           ret_queue)
    output = cmd_response_get(ret_queue)
    if output:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK
