from flask import Blueprint
from flask import request

from nat_worker import \
    create_snat, read_snat, update_snat, delete_snat, \
    create_dnat, read_dnat, update_dnat, delete_dnat
from const import API_PREFIX
from utils import json_http_response

nat_app = Blueprint('nat_app', __name__)


# SNAT


@nat_app.route(
    API_PREFIX + '/routers/<int:router_id>/snats/', methods=['POST'])
def snat_create_api(router_id):
    response, code = create_snat(request.data, router_id=router_id)
    return json_http_response(response), code


@nat_app.route(API_PREFIX + '/routers/<int:router_id>/snats/')
@nat_app.route(API_PREFIX + '/routers/<int:router_id>/snats/<int:rule_id>/')
def snat_read_api(router_id, rule_id=None):
    response, code = read_snat(router_id, rule_id)
    return json_http_response(response), code


@nat_app.route(API_PREFIX + '/routers/<int:router_id>/snats/', methods=['PUT'])
def snat_update_api(router_id):
    response, code = update_snat(request.data, router_id=router_id)
    return json_http_response(response), code


@nat_app.route(
    API_PREFIX + '/routers/<int:router_id>/snats/<int:rule_id>/',
    methods=['DELETE'])
def snat_delete_api(router_id, rule_id):
    response, code = delete_snat(router_id, rule_id)
    return json_http_response(response), code


# DNAT


@nat_app.route(
    API_PREFIX + '/routers/<int:router_id>/dnats/', methods=['POST'])
def dnat_create_api(router_id):
    response, code = create_dnat(request.data, router_id=router_id)
    return json_http_response(response), code


@nat_app.route(API_PREFIX + '/routers/<int:router_id>/dnats/')
@nat_app.route(API_PREFIX + '/routers/<int:router_id>/dnats/<int:rule_id>/')
def dnat_read_api(router_id, rule_id=None):
    response, code = read_dnat(router_id, rule_id)
    return json_http_response(response), code


@nat_app.route(API_PREFIX + '/routers/<int:router_id>/dnats/', methods=['PUT'])
def dnat_update_api(router_id):
    response, code = update_dnat(request.data, router_id=router_id)
    return json_http_response(response), code


@nat_app.route(
    API_PREFIX + '/routers/<int:router_id>/dnats/<int:rule_id>/',
    methods=['DELETE'])
def dnat_delete_api(router_id, rule_id):
    response, code = delete_dnat(router_id, rule_id)
    return json_http_response(response), code
