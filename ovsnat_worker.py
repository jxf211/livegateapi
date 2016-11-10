from pylc.models.livegateapi import OvsNat, is_valid_ip
from utils import call_system_sh, json_response, validate_json_obj
from const import SUCCESS, HTTP_OK, OVSNAT_SCRIPT, MIN_PORT, MAX_PORT, \
    SERVER_ERROR, HTTP_INTERNAL_SERVER_ERROR, \
    RESOURCE_NOT_FOUND, HTTP_NOT_FOUND
from logger import log


@validate_json_obj(obj_cls=OvsNat)
def create_ovsnat(ovsnat):
    log.debug('ovsnat: %r' % ovsnat.to_native())

    args = [
        OVSNAT_SCRIPT,
        'add-nat',
        ovsnat.bridge,
        str(ovsnat.port),
        ovsnat.ip,
        ovsnat.mac,
        str(ovsnat.target_port),
        ovsnat.target_ip,
        ovsnat.target_mac,
    ]
    rc, output = call_system_sh(args)
    if rc != 0:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK


def read_ovsnat(ovsnat_id=None):
    # TODO
    log.debug('ovsnat_id: %r' % ovsnat_id)
    return json_response(status=SUCCESS), HTTP_OK


def delete_ovsnat(ovsnat_id):
    id_seg = ovsnat_id.split('-')
    if id_seg is None or len(id_seg) != 3:
        return json_response(status=RESOURCE_NOT_FOUND), HTTP_NOT_FOUND

    if id_seg[0] not in OvsNat.bridge.choices:
        return json_response(status=RESOURCE_NOT_FOUND), HTTP_NOT_FOUND
    bridge = id_seg[0]

    if not id_seg[1].isdigit() or int(id_seg[1]) < MIN_PORT or \
            int(id_seg[1]) > MAX_PORT:
        return json_response(status=RESOURCE_NOT_FOUND), HTTP_NOT_FOUND
    target_port = id_seg[1]

    if not is_valid_ip(id_seg[2]):
        return json_response(status=RESOURCE_NOT_FOUND), HTTP_NOT_FOUND
    target_ip = id_seg[2]

    args = [
        OVSNAT_SCRIPT,
        'del-nat',
        bridge,
        target_port,
        target_ip,
    ]
    rc, output = call_system_sh(args)
    if rc != 0:
        return json_response(
            status=SERVER_ERROR, description=output
        ), HTTP_INTERNAL_SERVER_ERROR

    return json_response(status=SUCCESS), HTTP_OK
