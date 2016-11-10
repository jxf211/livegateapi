from flask import Blueprint
from flask import request

from tunnel_worker import \
    create_tunnel, read_tunnel, delete_tunnel, \
    create_tunnel_flow, read_tunnel_flow, delete_tunnel_flow
from const import API_PREFIX
from utils import json_http_response

tunnel_app = Blueprint('tunnel_app', __name__)


@tunnel_app.route(API_PREFIX + '/tunnels/', methods=['POST'])
def tunnel_create_api():
    response, code = create_tunnel(request.data)
    return json_http_response(response), code


@tunnel_app.route(API_PREFIX + '/tunnels/')
@tunnel_app.route(API_PREFIX + '/tunnels/<remote_ip>/')
def tunnel_read_api(remote_ip=None):
    response, code = read_tunnel(remote_ip)
    return json_http_response(response), code


@tunnel_app.route(API_PREFIX + '/tunnels/<remote_ip>/', methods=['DELETE'])
def tunnel_delete_api(remote_ip):
    response, code = delete_tunnel(remote_ip)
    return json_http_response(response), code


@tunnel_app.route(API_PREFIX + '/tunnel_flows/', methods=['POST'])
def tunnel_flow_create_api():
    response, code = create_tunnel_flow(request.data)
    return json_http_response(response), code


@tunnel_app.route(API_PREFIX + '/tunnel_flows/')
@tunnel_app.route(API_PREFIX + '/tunnel_flows/<flow_id>/')
def tunnel_flow_read_api(flow_id=None):
    """
    flow_id is like: <subnet_id>-<vif_id>
    i.e.,: 13-1345
           13-0
    vif_id=0 means tunnel flow for the whole subnet (broadcast flows)
    """
    response, code = read_tunnel_flow(flow_id)
    return json_http_response(response), code


@tunnel_app.route(
    API_PREFIX + '/tunnel_flows/<flow_id>/', methods=['DELETE'])
def tunnel_flow_delete_api(flow_id):
    """
    flow_id is like: <subnet_id>-<vif_id>
    i.e.,: 13-1345
           13-0
    vif_id=0 means tunnel flow for the whole subnet (broadcast flows)
    """
    response, code = delete_tunnel_flow(flow_id)
    return json_http_response(response), code
