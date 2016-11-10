from pylc.models.livegateapi import Tunnel, TunnelFlow
from utils import call_system_sh, json_response, validate_json_obj
from const import SUCCESS, HTTP_OK, SERVER_ERROR, HTTP_INTERNAL_SERVER_ERROR, \
    TUNNEL_BRIDGE, TUNNEL_SCRIPT, MAX_SUBNET, MAX_TUNNEL_MAC, \
    TUNNEL_FLOW_COOKIE_FORMAT, RESOURCE_NOT_FOUND, HTTP_NOT_FOUND
from logger import log
from task import PingTask


@validate_json_obj(obj_cls=Tunnel)
def create_tunnel(tunnel):
    log.debug('tunnel: %r' % tunnel.to_native())

    PingTask.add_peer_ip(tunnel.remote_ip)
    args = [
        TUNNEL_SCRIPT,
        'add-tunnel',
        tunnel.protocol,
        tunnel.remote_ip,
        'flow',
    ]
    rc, output = call_system_sh(args)
    if rc != 0:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK


def read_tunnel(remote_ip=None):
    # TODO
    log.debug('tunnel_id: %r' % remote_ip)
    return json_response(status=SUCCESS), HTTP_OK


def delete_tunnel(remote_ip):
    PingTask.del_peer_ip(remote_ip)
    args = [
        TUNNEL_SCRIPT,
        'del-tunnel',
        remote_ip,
    ]
    rc, output = call_system_sh(args)
    if rc != 0:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK


@validate_json_obj(obj_cls=TunnelFlow)
def create_tunnel_flow(tunnel_flow):
    log.debug('tunnel_flow: %r' % tunnel_flow.to_native())

    if tunnel_flow.vif_id == 0:
        args = [
            TUNNEL_SCRIPT,
            'set-vl2-policy',
            TUNNEL_FLOW_COOKIE_FORMAT % (tunnel_flow.subnet_id, 0),
            str(tunnel_flow.subnet_id),
            str(tunnel_flow.vlantag),
        ]
    else:
        args = [
            TUNNEL_SCRIPT,
            'set-vif-policy',
            TUNNEL_FLOW_COOKIE_FORMAT % (
                tunnel_flow.subnet_id, tunnel_flow.vif_id),
            str(tunnel_flow.subnet_id),
            str(tunnel_flow.vlantag),
            tunnel_flow.vif_mac,
        ]
    rc, output = call_system_sh(args)
    if rc != 0:
        log.error(output)
        return json_response(status=SERVER_ERROR), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK


def read_tunnel_flow(flow_id=None):
    # TODO
    log.debug('tunnel_flow_id: %r' % flow_id)
    return json_response(status=SUCCESS), HTTP_OK


def delete_tunnel_flow(flow_id):
    id_seg = flow_id.split('-')
    if id_seg is None or len(id_seg) != 2:
        return json_response(status=RESOURCE_NOT_FOUND), HTTP_NOT_FOUND

    if not id_seg[0].isdigit() or int(id_seg[0]) < 1 or \
            int(id_seg[0]) > MAX_SUBNET:
        return json_response(status=RESOURCE_NOT_FOUND), HTTP_NOT_FOUND
    subnet_id = int(id_seg[0])

    if not id_seg[1].isdigit() or int(id_seg[1]) < 0 or \
            int(id_seg[1]) > MAX_TUNNEL_MAC:
        return json_response(status=RESOURCE_NOT_FOUND), HTTP_NOT_FOUND
    vif_id = int(id_seg[1])

    args = [
        TUNNEL_SCRIPT,
        'clear-policy',
        TUNNEL_BRIDGE,
        TUNNEL_FLOW_COOKIE_FORMAT % (subnet_id, vif_id),
        str(-1),
    ]
    rc, output = call_system_sh(args)
    if rc != 0:
        log.error(output)
        return json_response(status=SERVER_ERROR), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK
