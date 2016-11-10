from flask import Blueprint
from flask import request

from ovsnat_worker import \
    create_ovsnat, read_ovsnat, delete_ovsnat
from const import API_PREFIX
from utils import json_http_response

ovsnat_app = Blueprint('ovsnat_app', __name__)


@ovsnat_app.route(API_PREFIX + '/ovsnats/', methods=['POST'])
def ovsnat_create_api():
    response, code = create_ovsnat(request.data)
    return json_http_response(response), code


@ovsnat_app.route(API_PREFIX + '/ovsnats/')
@ovsnat_app.route(API_PREFIX + '/ovsnats/<ovsnat_id>/')
def ovsnat_read_api(ovsnat_id=None):
    """
    ovsnat_id is like: <bridge_name>-<target_port>-<target_ip>
    i.e.,: UPLINK-20000-8.8.8.8
    """
    response, code = read_ovsnat(ovsnat_id)
    return json_http_response(response), code


@ovsnat_app.route(API_PREFIX + '/ovsnats/<ovsnat_id>/', methods=['DELETE'])
def ovsnat_delete_api(ovsnat_id):
    """
    ovsnat_id is like: <bridge_name>-<target_port>-<target_ip>
    i.e.,: UPLINK-20000-8.8.8.8
    """
    response, code = delete_ovsnat(ovsnat_id)
    return json_http_response(response), code
