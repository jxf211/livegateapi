from flask import Blueprint
from flask import request

from route_worker import \
    create_route, read_route, delete_route
from const import API_PREFIX
from utils import json_http_response

route_app = Blueprint('route_app', __name__)


@route_app.route(
    API_PREFIX + '/routers/<int:router_id>/routes/', methods=['POST'])
def route_create_api(router_id):
    response, code = create_route(request.data, router_id=router_id)
    return json_http_response(response), code


@route_app.route(API_PREFIX + '/routers/<int:router_id>/routes/')
@route_app.route(API_PREFIX + '/routers/<int:router_id>/routes/<route_id>/')
def route_read_api(router_id, route_id=None):
    """
    route_id is like: <dst_address>-<dst_network>
    i.e.,: 8.8.0.0-255.255.0.0
    """
    response, code = read_route(router_id, route_id)
    return json_http_response(response), code


@route_app.route(
    API_PREFIX + '/routers/<int:router_id>/routes/<route_id>/',
    methods=['DELETE'])
def route_delete_api(router_id, route_id):
    """
    route_id is like: <dst_address>-<dst_network>
    i.e.,: 8.8.0.0-255.255.0.0
    """
    response, code = delete_route(router_id, route_id)
    return json_http_response(response), code
