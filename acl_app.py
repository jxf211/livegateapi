from flask import Blueprint
from flask import request

from acl_worker import \
    create_in_acl, read_in_acl, update_in_acl, delete_in_acl, \
    create_out_acl, read_out_acl, update_out_acl, delete_out_acl, \
    create_fw_acl, read_fw_acl, update_fw_acl, delete_fw_acl
from const import API_PREFIX
from utils import json_http_response

acl_app = Blueprint('acl_app', __name__)


# INPUT


@acl_app.route(
    API_PREFIX + '/routers/<int:router_id>/input_acls/', methods=['POST'])
def in_acl_create_api(router_id):
    response, code = create_in_acl(request.data, router_id=router_id)
    return json_http_response(response), code


@acl_app.route(API_PREFIX + '/routers/<int:router_id>/input_acls/')
@acl_app.route(
    API_PREFIX + '/routers/<int:router_id>/input_acls/<int:rule_id>/')
def in_acl_read_api(router_id, rule_id=None):
    response, code = read_in_acl(router_id, rule_id)
    return json_http_response(response), code


@acl_app.route(
    API_PREFIX + '/routers/<int:router_id>/input_acls/', methods=['PUT'])
def in_acl_update_api(router_id):
    response, code = update_in_acl(request.data, router_id=router_id)
    return json_http_response(response), code


@acl_app.route(
    API_PREFIX + '/routers/<int:router_id>/input_acls/<int:rule_id>/',
    methods=['DELETE'])
def in_acl_delete_api(router_id, rule_id):
    response, code = delete_in_acl(router_id, rule_id)
    return json_http_response(response), code


# OUTPUT


@acl_app.route(
    API_PREFIX + '/routers/<int:router_id>/output_acls/', methods=['POST'])
def out_acl_create_api(router_id):
    response, code = create_out_acl(request.data, router_id=router_id)
    return json_http_response(response), code


@acl_app.route(API_PREFIX + '/routers/<int:router_id>/output_acls/')
@acl_app.route(
    API_PREFIX + '/routers/<int:router_id>/output_acls/<int:rule_id>/')
def out_acl_read_api(router_id, rule_id=None):
    response, code = read_out_acl(router_id, rule_id)
    return json_http_response(response), code


@acl_app.route(
    API_PREFIX + '/routers/<int:router_id>/output_acls/', methods=['PUT'])
def out_acl_update_api(router_id):
    response, code = update_out_acl(request.data, router_id=router_id)
    return json_http_response(response), code


@acl_app.route(
    API_PREFIX + '/routers/<int:router_id>/output_acls/<int:rule_id>/',
    methods=['DELETE'])
def out_acl_delete_api(router_id, rule_id):
    response, code = delete_out_acl(router_id, rule_id)
    return json_http_response(response), code


# FORWARD


@acl_app.route(
    API_PREFIX + '/routers/<int:router_id>/forward_acls/', methods=['POST'])
def fw_acl_create_api(router_id):
    response, code = create_fw_acl(request.data, router_id=router_id)
    return json_http_response(response), code


@acl_app.route(API_PREFIX + '/routers/<int:router_id>/forward_acls/')
@acl_app.route(
    API_PREFIX + '/routers/<int:router_id>/forward_acls/<int:rule_id>/')
def fw_acl_read_api(router_id, rule_id=None):
    response, code = read_fw_acl(router_id, rule_id)
    return json_http_response(response), code


@acl_app.route(
    API_PREFIX + '/routers/<int:router_id>/forward_acls/', methods=['PUT'])
def fw_acl_update_api(router_id):
    response, code = update_fw_acl(request.data, router_id=router_id)
    return json_http_response(response), code


@acl_app.route(
    API_PREFIX + '/routers/<int:router_id>/forward_acls/<int:rule_id>/',
    methods=['DELETE'])
def fw_acl_delete_api(router_id, rule_id):
    response, code = delete_fw_acl(router_id, rule_id)
    return json_http_response(response), code
