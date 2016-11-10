from flask import Blueprint
from flask import request

from cmd_worker import put_cmd
from const import API_PREFIX
from utils import json_http_response

cmd_app = Blueprint('cmd_app', __name__)


@cmd_app.route(
    API_PREFIX + '/routers/<int:router_id>/commands/', methods=['PUT'])
def cmd_put_api(router_id):
    """Exec a cmd

    HTTP request body:
    /v1/cmds/
    {
      "COMMAND": "ping/arping",
      "COMMAND": "ping",
      "IF_TYPE": "WAN/LAN",
      "IF_TYPE": "WAN",
      "IF_INDEX": 1,
      "SOURCE": "1.2.3.1",
      "TARGET": "1.2.3.4",
      "INTERVAL": 1000
    }

    HTTP response body:
    {
      "DATA": {
        "OUTPUT": "PING 172.21.102.175 (172.21.102.175) 56(84) bytes of data.
64 bytes from 172.21.102.175: icmp_seq=1 ttl=62 time=0.613 ms
64 bytes from 172.21.102.175: icmp_seq=2 ttl=62 time=0.423 ms
64 bytes from 172.21.102.175: icmp_seq=3 ttl=62 time=0.452 ms
64 bytes from 172.21.102.175: icmp_seq=4 ttl=62 time=0.429 ms
64 bytes from 172.21.102.175: icmp_seq=5 ttl=62 time=0.440 ms

--- 172.21.102.175 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4001ms
rtt min/avg/max/mdev = 0.423/0.471/0.613/0.074 ms",
      }
    }
    """
    response, code = put_cmd(request.data, router_id=router_id)
    return json_http_response(response), code
