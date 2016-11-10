from flask import Blueprint
from flask import request

from valve_worker import \
    create_valve, read_valve, update_valve, delete_valve, \
    create_wan, read_wan, update_wan, delete_wan, \
    create_lan, read_lan, update_lan, delete_lan
from const import API_PREFIX
from utils import json_http_response

valve_app = Blueprint('valve_app', __name__)


# Router


@valve_app.route(API_PREFIX + '/valves/', methods=['POST'])
def valve_create_api():
    response, code = create_valve(request.data)
    return json_http_response(response), code


@valve_app.route(API_PREFIX + '/valves/<int:router_id>/')
def valve_read_api(router_id):
    response, code = read_valve(router_id)
    return json_http_response(response), code


@valve_app.route(API_PREFIX + '/valves/<int:router_id>/', methods=['PUT'])
def valve_update_api(router_id):
    response, code = update_valve(request.data, router_id=router_id)
    return json_http_response(response), code


@valve_app.route(API_PREFIX + '/valves/<int:router_id>/', methods=['DELETE'])
def valve_delete_api(router_id):
    response, code = delete_valve(router_id, True)
    return json_http_response(response), code


# Wan


@valve_app.route(
    API_PREFIX + '/valves/<int:router_id>/wans/', methods=['POST'])
def wan_create_api(router_id):
    response, code = create_wan(request.data, router_id=router_id)
    return json_http_response(response), code


@valve_app.route(
    API_PREFIX + '/valves/<int:router_id>/wans/<int:if_index>/')
def wan_read_api(router_id, if_index):
    response, code = read_wan(router_id, if_index)
    return json_http_response(response), code


@valve_app.route(
    API_PREFIX + '/valves/<int:router_id>/wans/<int:if_index>/',
    methods=['PUT'])
def wan_update_api(router_id, if_index):
    response, code = update_wan(
        request.data, router_id=router_id, if_index=if_index)
    return json_http_response(response), code


@valve_app.route(
    API_PREFIX + '/valves/<int:router_id>/wans/<int:if_index>/',
    methods=['DELETE'])
def wan_delete_api(router_id, if_index):
    response, code = delete_wan(router_id, if_index)
    return json_http_response(response), code


# Lan


@valve_app.route(
    API_PREFIX + '/valves/<int:router_id>/lans/', methods=['POST'])
def lan_create_api(router_id):
    response, code = create_lan(request.data, router_id=router_id)
    return json_http_response(response), code


@valve_app.route(
    API_PREFIX + '/valves/<int:router_id>/lans/<int:if_index>/')
def lan_read_api(router_id, if_index):
    response, code = read_lan(router_id, if_index)
    return json_http_response(response), code


@valve_app.route(
    API_PREFIX + '/valves/<int:router_id>/lans/<int:if_index>/',
    methods=['PUT'])
def lan_update_api(router_id, if_index):
    response, code = update_lan(
        request.data, router_id=router_id, if_index=if_index)
    return json_http_response(response), code


@valve_app.route(
    API_PREFIX + '/valves/<int:router_id>/lans/<int:if_index>/',
    methods=['DELETE'])
def lan_delete_api(router_id, if_index):
    response, code = delete_lan(router_id, if_index)
    return json_http_response(response), code
