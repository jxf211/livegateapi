from pylc.models.livegateapi import Vpn
from utils import json_response, validate_json_obj, \
    validate_json_obj_list
from const import SUCCESS, HTTP_OK, ROUTER_SCRIPT, \
    SERVER_ERROR, HTTP_INTERNAL_SERVER_ERROR
from logger import log
from task import cmd_waiting_queues_put, cmd_response_get, router_hash, \
    PseudoGeventQueue


@validate_json_obj(obj_cls=Vpn)
def create_vpn(vpn, router_id):
    return config_vpn(router_id, vpn)


def read_vpn(router_id, vpn_name=None):
    # TODO
    log.debug('vpn_id: %d-%r' % (router_id, vpn_name))
    return json_response(status=SUCCESS), HTTP_OK


@validate_json_obj_list(obj_cls=Vpn)
def update_vpn(vpns, router_id):
    key = ('update', 'vpn', str(router_id))
    message = []
    args = [
        ROUTER_SCRIPT,
        'flush', 'vpn',
        str(router_id),
    ]
    message.append(args)

    for vpn in vpns:
        args = get_config_vpn_args(router_id, vpn)
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


def delete_vpn(router_id, vpn_name):
    key = ('delete', 'vpn', str(router_id), vpn_name)
    args = [
        ROUTER_SCRIPT,
        'delete', 'vpn',
        str(router_id),
        vpn_name,
    ]
    ret_queue = PseudoGeventQueue()
    cmd_waiting_queues_put(router_id,
                           router_hash,
                           key,
                           args,
                           ret_queue)
    output = cmd_response_get(ret_queue)
    if output:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK


def get_config_vpn_args(router_id, vpn):
    args = [
        ROUTER_SCRIPT,
        'add', 'vpn',
        str(router_id),
        vpn.name,
        str(vpn.isp),
        vpn.left,
        vpn.lnetwork.address,
        vpn.lnetwork.netmask,
        vpn.right,
        vpn.rnetwork.address,
        vpn.rnetwork.netmask,
        vpn.psk,
    ]
    return args


def config_vpn(router_id, vpn):
    log.debug('router_id: %r, vpn: %r' % (router_id, vpn.to_native()))
    key = ('add', 'vpn', str(router_id), vpn.name)
    args = get_config_vpn_args(router_id, vpn)
    ret_queue = PseudoGeventQueue()
    cmd_waiting_queues_put(router_id,
                           router_hash,
                           key,
                           args,
                           ret_queue)
    output = cmd_response_get(ret_queue)
    if output:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK
