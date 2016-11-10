from pylc.models.livegateapi import Nat
from utils import json_response, validate_json_obj, \
    validate_json_obj_list
from const import SUCCESS, HTTP_OK, INVALID_POST_DATA, HTTP_BAD_REQUEST, \
    SERVER_ERROR, HTTP_INTERNAL_SERVER_ERROR, \
    ROUTER_SCRIPT, SNAT, DNAT, NF_APPEND, ANY_IF, MIN_IPV4, MAX_IPV4
from logger import log
from task import cmd_waiting_queues_put, cmd_response_get, router_hash, \
    PseudoGeventQueue

# SNAT


@validate_json_obj(obj_cls=Nat)
def create_snat(nat, router_id):
    return create_nat(SNAT, router_id, nat)


def read_snat(router_id, rule_id=None):
    return read_nat(SNAT, router_id, rule_id)


@validate_json_obj_list(obj_cls=Nat)
def update_snat(nats, router_id):
    return update_nat(SNAT, router_id, nats)


def delete_snat(router_id, rule_id):
    return delete_nat(SNAT, router_id, rule_id)


# DNAT


@validate_json_obj(obj_cls=Nat)
def create_dnat(nat, router_id):
    return create_nat(DNAT, router_id, nat)


def read_dnat(router_id, rule_id=None):
    return read_nat(DNAT, router_id, rule_id)


@validate_json_obj_list(obj_cls=Nat)
def update_dnat(nats, router_id):
    return update_nat(DNAT, router_id, nats)


def delete_dnat(router_id, rule_id):
    return delete_nat(DNAT, router_id, rule_id)


# utils


def create_nat(nat_type, router_id, nat):
    return config_nat(NF_APPEND, nat_type, router_id, None, nat)


def read_nat(nat_type, router_id, rule_id=None):
    # TODO
    log.debug('%s nat_id: %d-%r' % (nat_type, router_id, rule_id))
    return json_response(status=SUCCESS), HTTP_OK


def update_nat(nat_type, router_id, nats):
    key = ('update', 'nat', nat_type, str(router_id))
    message = []
    args = [
        ROUTER_SCRIPT,
        'flush', 'nat',
        nat_type,
        str(router_id),
    ]
    message.append(args)

    for nat in sorted(nats, cmp=lambda x, y: cmp(x.rule_id, y.rule_id)):
        args, constrains = get_config_nat_args(NF_APPEND, nat_type,
                                               router_id, nat)
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


def delete_nat(nat_type, router_id, rule_id):
    key = ('delete', 'nat', nat_type, str(router_id), str(rule_id))
    args = [
        ROUTER_SCRIPT,
        'delete', 'nat',
        nat_type,
        str(router_id),
        str(rule_id),
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


def get_config_nat_args(nf_command, nat_type, router_id, nat):
    if nat_type == SNAT:
        if nat.target.min_address != MIN_IPV4 or \
                nat.target.max_address != MAX_IPV4:
            nat.target.if_type = ANY_IF
            nat.target.if_index = 0

    constrains = None
    if nat_type == SNAT and nat.match.if_type != ANY_IF:
        constrains = 'Can not set MATCH IF_TYPE if NAT_TYPE is SNAT'
    elif nat_type == DNAT and nat.target.if_type != ANY_IF:
        constrains = 'Can not set TARGET IF_TYPE if NAT_TYPE is DNAT'

    if constrains is not None:
        return [], constrains

    args = [
        ROUTER_SCRIPT,
        nf_command, 'nat',
        nat_type,
        str(router_id),
        str(nat.rule_id),
        str(nat.isp),
        str(nat.protocol),
        nat.match.if_type,
        str(nat.match.if_index),
        nat.match.min_address,
        nat.match.max_address,
        str(nat.match.min_port),
        str(nat.match.max_port),
        nat.target.if_type,
        str(nat.target.if_index),
        nat.target.min_address,
        nat.target.max_address,
        str(nat.target.min_port),
        str(nat.target.max_port),
    ]
    return args, constrains


def config_nat(nf_command, nat_type, router_id, rule_id, nat):
    log.debug('nf_command: %s, nat_id: %r-%r, nat: %r' % (
        nf_command, router_id, rule_id, nat.to_native()))

    args, constrains = get_config_nat_args(nf_command, nat_type,
                                           router_id, nat)
    if constrains is not None:
        log.info(constrains)
        return json_response(
            status=INVALID_POST_DATA, description=constrains
        ), HTTP_BAD_REQUEST

    key = (nf_command, 'nat', nat_type, str(router_id), str(nat.rule_id))
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
