from pylc.models.livegateapi import Route
from schematics.types import IPv4Type
from utils import json_response, validate_json_obj
from const import SUCCESS, HTTP_OK, ROUTER_SCRIPT, \
    SERVER_ERROR, HTTP_INTERNAL_SERVER_ERROR, \
    RESOURCE_NOT_FOUND, HTTP_NOT_FOUND
from logger import log
from task import cmd_waiting_queues_put, cmd_response_get, router_hash, \
    PseudoGeventQueue


@validate_json_obj(obj_cls=Route)
def create_route(route, router_id):
    log.debug('router_id: %r, route: %r' % (router_id, route.to_native()))

    key = ('create', 'route', str(router_id),
           route.dst_network.address,
           route.dst_network.netmask)
    ret_queue = PseudoGeventQueue()
    args = [
        ROUTER_SCRIPT,
        'add', 'route',
        str(router_id),
        route.dst_network.address,
        route.dst_network.netmask,
        route.next_hop,
        str(route.if_type),
        str(route.if_index),
        str(route.isp),
    ]
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


def read_route(router_id, route_id=None):
    # TODO
    log.debug('route_id: %d-%r' % (router_id, route_id))
    return json_response(status=SUCCESS), HTTP_OK


def delete_route(router_id, route_id):
    id_seg = route_id.split('-')
    if id_seg is None or len(id_seg) != 2:
        return json_response(status=RESOURCE_NOT_FOUND), HTTP_NOT_FOUND

    for s in id_seg:
        if not IPv4Type.valid_ip(s):
            return json_response(status=RESOURCE_NOT_FOUND), HTTP_NOT_FOUND
    dst_address, dst_netmask = id_seg

    key = ('delete', 'route', str(router_id), dst_address, dst_netmask)
    ret_queue = PseudoGeventQueue()
    args = [
        ROUTER_SCRIPT,
        'delete', 'route',
        str(router_id),
        dst_address,
        dst_netmask,
    ]
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
