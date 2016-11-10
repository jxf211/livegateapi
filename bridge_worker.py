from pylc.models.livegateapi import Bridge
from utils import call_system_sh, json_response, validate_json_obj
from const import SUCCESS, HTTP_OK, TUNNEL_SCRIPT, SYSCONF_SCRIPT, \
    SERVER_ERROR, HTTP_INTERNAL_SERVER_ERROR, \
    UPLINK_BRIDGE, TUNNEL_BRIDGE
from logger import log


def read_bridge(bridge_name=None):
    # TODO
    log.debug('bridge_name: %r' % bridge_name)
    return json_response(status=SUCCESS), HTTP_OK


@validate_json_obj(obj_cls=Bridge)
def update_bridge(bridge, bridge_name):
    log.debug('bridge_name: %s' % bridge_name)

    if bridge.name == UPLINK_BRIDGE and \
            bridge.ip is not None and bridge.gateway is not None:
        args = [
            SYSCONF_SCRIPT,
            bridge.name,
            bridge.ip.address,
            bridge.ip.netmask,
            bridge.gateway,
        ]
    if bridge.name == TUNNEL_BRIDGE and bridge.qos is not None:
        args = [
            TUNNEL_SCRIPT,
            'set-qos',
            str(bridge.qos.min_bandwidth),
            str(bridge.qos.max_bandwidth),
        ]
    rc, output = call_system_sh(args)
    if rc != 0:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK
