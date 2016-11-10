from flask import Blueprint
from flask import request

from bridge_worker import read_bridge, update_bridge
from const import API_PREFIX
from utils import json_http_response

bridge_app = Blueprint('bridge_app', __name__)


@bridge_app.route(API_PREFIX + '/bridges/')
@bridge_app.route(API_PREFIX + '/bridges/<bridge_name>/')
def bridge_read_api(bridge_name=None):
    response, code = read_bridge(bridge_name)
    return json_http_response(response), code


@bridge_app.route(API_PREFIX + '/bridges/<bridge_name>/', methods=[
    'PATCH', 'POST'])
def bridge_update_api(bridge_name):
    """Config bridge IP/QoS

    HTTP request body:
    /v1/bridges/UPLINK/
    {
      "NAME": "UPLINK",
      "IP": {
        "ADDRESS": "192.168.2.113",
        "NETMASK": "255.255.0.0"
      },
      "GATEWAY": "192.168.0.1"
    }

    /v1/bridges/TUNNEL/
    {
      "NAME": "TUNNEL",
      "QOS": {
        "MIN_BANDWIDTH": 10240000,
        "MAX_BANDWIDTH": 10240000
      }
    }
    """
    response, code = update_bridge(request.data, bridge_name=bridge_name)
    return json_http_response(response), code
