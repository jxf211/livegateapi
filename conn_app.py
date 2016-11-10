from flask import Blueprint
from flask import request

from conn_worker import \
    create_conn_limit, read_conn_limit, update_conn_limit, delete_conn_limit
from const import API_PREFIX
from utils import json_http_response

conn_app = Blueprint('conn_app', __name__)


@conn_app.route(
    API_PREFIX + '/routers/<int:router_id>/conntracks/', methods=['POST'])
def conn_create_api(router_id):
    response, code = create_conn_limit(request.data, router_id=router_id)
    return json_http_response(response), code


@conn_app.route(API_PREFIX + '/routers/<int:router_id>/conntracks/')
def conn_read_api(router_id):
    response, code = read_conn_limit(router_id)
    return json_http_response(response), code


@conn_app.route(
    API_PREFIX + '/routers/<int:router_id>/conntracks/', methods=['PUT'])
def conn_update_api(router_id):
    response, code = update_conn_limit(request.data, router_id=router_id)
    return json_http_response(response), code


@conn_app.route(API_PREFIX + '/routers/<int:router_id>/conntracks/')
@conn_app.route(
    API_PREFIX + '/routers/<int:router_id>/conntracks/', methods=['DELETE'])
def conn_delete_api(router_id):
    response, code = delete_conn_limit(router_id)
    return json_http_response(response), code
