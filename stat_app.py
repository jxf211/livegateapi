from flask import Blueprint
from flask import request

from stat_worker import nsp_stat
from const import API_PREFIX
from utils import json_http_response
from reporter import report_bootup

stat_app = Blueprint('stat_app', __name__)


@stat_app.route(API_PREFIX + '/nsp-stats/')
def nsp_stat_read_api():
    """
    request args: realtime=true/false
                  lcc_talker_ip=172.16.26.2
    """
    lcc_talker_ip = request.args.get('lcc_talker_ip', type=str)
    if lcc_talker_ip:
        report_bootup(lcc_talker_ip)

    if request.args.get('realtime', 'false') == 'false':
        response, code = nsp_stat()
    else:
        response, code = nsp_stat(realtime=True)
    return json_http_response(response), code
