from flask import Blueprint
from flask import request

from vpn_worker import \
    create_vpn, read_vpn, update_vpn, delete_vpn
from const import API_PREFIX
from utils import json_http_response

vpn_app = Blueprint('vpn_app', __name__)


@vpn_app.route(
    API_PREFIX + '/routers/<int:router_id>/vpns/', methods=['POST'])
def vpn_create_api(router_id):
    response, code = create_vpn(request.data, router_id=router_id)
    return json_http_response(response), code


@vpn_app.route(API_PREFIX + '/routers/<int:router_id>/vpns/')
@vpn_app.route(API_PREFIX + '/routers/<int:router_id>/vpns/<vpn_name>/')
def vpn_read_api(router_id, vpn_name=None):
    response, code = read_vpn(router_id, vpn_name)
    return json_http_response(response), code


@vpn_app.route(API_PREFIX + '/routers/<int:router_id>/vpns/', methods=['PUT'])
def vpn_update_api(router_id):
    response, code = update_vpn(request.data, router_id=router_id)
    return json_http_response(response), code


@vpn_app.route(
    API_PREFIX + '/routers/<int:router_id>/vpns/<vpn_name>/',
    methods=['DELETE'])
def vpn_delete_api(router_id, vpn_name):
    response, code = delete_vpn(router_id, vpn_name)
    return json_http_response(response), code
