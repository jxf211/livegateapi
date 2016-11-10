from flask import Blueprint
from flask import request

from router_worker import \
    create_router, read_router, update_router, delete_router, \
    create_wan, read_wan, update_wan, delete_wan, \
    create_lan, read_lan, update_lan, delete_lan
from const import API_PREFIX
from utils import json_http_response

router_app = Blueprint('router_app', __name__)


# Router


@router_app.route(API_PREFIX + '/routers/', methods=['POST'])
def router_create_api():
    response, code = create_router(request.data)
    return json_http_response(response), code


@router_app.route(API_PREFIX + '/routers/<int:router_id>/')
def router_read_api(router_id):
    response, code = read_router(router_id)
    return json_http_response(response), code


@router_app.route(API_PREFIX + '/routers/<int:router_id>/', methods=['PUT'])
def router_update_api(router_id):
    response, code = update_router(request.data, router_id=router_id)
    return json_http_response(response), code


@router_app.route(API_PREFIX + '/routers/<int:router_id>/', methods=['DELETE'])
def router_delete_api(router_id):
    response, code = delete_router(router_id, True)
    return json_http_response(response), code


# Wan


@router_app.route(
    API_PREFIX + '/routers/<int:router_id>/wans/', methods=['POST'])
def wan_create_api(router_id):
    response, code = create_wan(request.data, router_id=router_id)
    return json_http_response(response), code


@router_app.route(
    API_PREFIX + '/routers/<int:router_id>/wans/<int:if_index>/')
def wan_read_api(router_id, if_index):
    response, code = read_wan(router_id, if_index)
    return json_http_response(response), code


@router_app.route(
    API_PREFIX + '/routers/<int:router_id>/wans/<int:if_index>/',
    methods=['PUT'])
def wan_update_api(router_id, if_index):
    response, code = update_wan(
        request.data, router_id=router_id, if_index=if_index)
    return json_http_response(response), code


@router_app.route(
    API_PREFIX + '/routers/<int:router_id>/wans/<int:if_index>/',
    methods=['DELETE'])
def wan_delete_api(router_id, if_index):
    response, code = delete_wan(router_id, if_index)
    return json_http_response(response), code


# Lan


@router_app.route(
    API_PREFIX + '/routers/<int:router_id>/lans/', methods=['POST'])
def lan_create_api(router_id):
    response, code = create_lan(request.data, router_id=router_id)
    return json_http_response(response), code


@router_app.route(
    API_PREFIX + '/routers/<int:router_id>/lans/<int:if_index>/')
def lan_read_api(router_id, if_index):
    response, code = read_lan(router_id, if_index)
    return json_http_response(response), code


@router_app.route(
    API_PREFIX + '/routers/<int:router_id>/lans/<int:if_index>/',
    methods=['PUT'])
def lan_update_api(router_id, if_index):
    response, code = update_lan(
        request.data, router_id=router_id, if_index=if_index)
    return json_http_response(response), code


@router_app.route(
    API_PREFIX + '/routers/<int:router_id>/lans/<int:if_index>/',
    methods=['DELETE'])
def lan_delete_api(router_id, if_index):
    response, code = delete_lan(router_id, if_index)
    return json_http_response(response), code
