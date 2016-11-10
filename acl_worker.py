from pylc.models.livegateapi import Acl
from utils import json_response, validate_json_obj, \
    validate_json_obj_list
from const import SUCCESS, HTTP_OK, INVALID_POST_DATA, HTTP_BAD_REQUEST, \
    SERVER_ERROR, HTTP_INTERNAL_SERVER_ERROR, \
    ROUTER_SCRIPT, INPUT, OUTPUT, FORWARD, NF_APPEND, ANY_IF
from logger import log
from task import cmd_waiting_queues_put, cmd_response_get, router_hash, \
    PseudoGeventQueue

# INPUT


@validate_json_obj(obj_cls=Acl)
def create_in_acl(acl, router_id):
    return create_acl(INPUT, router_id, acl)


def read_in_acl(router_id, rule_id=None):
    return read_acl(INPUT, router_id, rule_id)


@validate_json_obj_list(obj_cls=Acl)
def update_in_acl(acls, router_id):
    return update_acl(INPUT, router_id, acls)


def delete_in_acl(router_id, rule_id):
    return delete_acl(INPUT, router_id, rule_id)


# OUTPUT


@validate_json_obj(obj_cls=Acl)
def create_out_acl(acl, router_id):
    return create_acl(OUTPUT, router_id, acl)


def read_out_acl(router_id, rule_id=None):
    return read_acl(OUTPUT, router_id, rule_id)


@validate_json_obj_list(obj_cls=Acl)
def update_out_acl(acls, router_id):
    return update_acl(OUTPUT, router_id, acls)


def delete_out_acl(router_id, rule_id):
    return delete_acl(OUTPUT, router_id, rule_id)


# FORWARD


@validate_json_obj(obj_cls=Acl)
def create_fw_acl(acl, router_id):
    return create_acl(FORWARD, router_id, acl)


def read_fw_acl(router_id, rule_id=None):
    return read_acl(FORWARD, router_id, rule_id)


@validate_json_obj_list(obj_cls=Acl)
def update_fw_acl(acls, router_id):
    return update_acl(FORWARD, router_id, acls)


def delete_fw_acl(router_id, rule_id):
    return delete_acl(FORWARD, router_id, rule_id)


# utils


def create_acl(acl_type, router_id, acl):
    return config_acl(NF_APPEND, acl_type, router_id, None, acl)


def read_acl(acl_type, router_id, rule_id=None):
    # TODO
    log.debug('%s acl_id: %d-%r' % (acl_type, router_id, rule_id))
    return json_response(status=SUCCESS), HTTP_OK


def update_acl(acl_type, router_id, acls):
    key = ('update', 'acl', acl_type, str(router_id))
    message = []
    args = [
        ROUTER_SCRIPT,
        'flush', 'acl',
        acl_type,
        str(router_id),
    ]
    message.append(args)

    for acl in sorted(acls, cmp=lambda x, y: cmp(x.rule_id, y.rule_id)):
        args, constrains = get_config_acl_args(NF_APPEND, acl_type,
                                               router_id, acl)
        if constrains is not None:
            return json_response(
                status=INVALID_POST_DATA, description=constrains
            ), HTTP_BAD_REQUEST
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


def delete_acl(acl_type, router_id, rule_id):
    key = ('delete', 'acl', acl_type, str(router_id), str(rule_id))
    ret_queue = PseudoGeventQueue()
    args = [
        ROUTER_SCRIPT,
        'delete', 'acl',
        acl_type,
        str(router_id),
        str(rule_id),
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


def get_config_acl_args(nf_command, acl_type, router_id, acl):
    constrains = None
    if acl_type == INPUT and acl.match_dst.if_type != ANY_IF:
        constrains = 'Can not set MATCH_DST IF_TYPE for input_acls'
    elif acl_type == OUTPUT and acl.match_src.if_type != ANY_IF:
        constrains = 'Can not set MATCH_SRC IF_TYPE for output_acls'

    if constrains is not None:
        return [], constrains

    args = [
        ROUTER_SCRIPT,
        nf_command, 'acl',
        acl_type,
        str(router_id),
        str(acl.rule_id),
        str(acl.protocol),
        acl.match_src.if_type,
        str(acl.match_src.if_index),
        acl.match_src.min_address,
        acl.match_src.max_address,
        str(acl.match_src.min_port),
        str(acl.match_src.max_port),
        acl.match_dst.if_type,
        str(acl.match_dst.if_index),
        acl.match_dst.min_address,
        acl.match_dst.max_address,
        str(acl.match_dst.min_port),
        str(acl.match_dst.max_port),
        acl.action,
    ]
    return args, constrains


def config_acl(nf_command, acl_type, router_id, rule_id, acl):
    log.debug('nf_command: %s, acl_id: %r-%r, acl: %r' % (
        nf_command, router_id, rule_id, acl.to_native()))

    args, constrains = get_config_acl_args(nf_command,
                                           acl_type,
                                           router_id,
                                           acl)
    if constrains is not None:
        log.info(constrains)
        return json_response(
            status=INVALID_POST_DATA, description=constrains
        ), HTTP_BAD_REQUEST

    key = (nf_command, 'acl', acl_type, str(router_id), str(acl.rule_id))
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
