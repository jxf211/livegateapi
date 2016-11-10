import simplejson as json
import datetime
import commands
import struct
import socket
import fcntl

from flask import Response
from logger import log
from const import DEBUG, SUCCESS, DATE_PATTEN, \
    INVALID_POST_DATA, HTTP_BAD_REQUEST


class LCJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime(DATE_PATTEN)
        else:
            return json.JSONEncoder.default(self, obj)


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


def json_http_response(data):
    return Response(data, content_type='application/json; charset=utf-8')


def json_response(status=SUCCESS, description='', data=None, type=None):
    if data is None:
        info = {'OPT_STATUS': status, 'DESCRIPTION': description}
    else:
        if type is None:
            if isinstance(data, list):
                if data:
                    type = data[0].__class__.__name__
                else:
                    type = None
            else:
                type = data.__class__.__name__
        info = {
            'OPT_STATUS': status,
            'DESCRIPTION': description,
            'DATA': data,
            'TYPE': type
        }
    return LCJSONEncoder().encode(info)


def call_system_sh(args):
    """call system
    """
    cmd = 'sh -x ' if DEBUG else 'sh '
    cmd += ' '.join(['"' + str(a) + '"' for a in args]) + ' 2>&1'
    log.debug(cmd)
    rc, output = commands.getstatusoutput(cmd)
    if rc == 0:
        if output and DEBUG:
            log.debug(output)
    else:
        log.error(output)
    return (rc, output)


def validate_json_obj_list(obj_cls):
    def validate_obj(func):
        def __decorator(request_data, **obj_id):
            try:
                json_data = json.loads(request_data)
                if not isinstance(json_data, list):
                    return json_response(
                        status=INVALID_POST_DATA,
                        description='Payload must be a list'
                    ), HTTP_BAD_REQUEST

                obj_list = []
                for data in json_data:
                    obj = obj_cls(data)
                    obj.validate()
                    obj_list.append(obj)
                return func(obj_list, **obj_id)
            except Exception, e:
                log.error(request_data)
                log.error(e)
                return json_response(
                    status=INVALID_POST_DATA, description=str(e)
                ), HTTP_BAD_REQUEST

        return __decorator

    return validate_obj


def validate_json_obj(obj_cls):
    def validate_obj(func):
        def __decorator(request_data, **obj_id):
            try:
                obj = obj_cls(json.loads(request_data))
                obj.validate()
                return func(obj, **obj_id)
            except Exception, e:
                import traceback
                log.error(traceback.format_exc())
                log.error(request_data)
                log.error(e)
                return json_response(
                    status=INVALID_POST_DATA, description=str(e)
                ), HTTP_BAD_REQUEST

        return __decorator

    return validate_obj


def ip_to_bin(ipaddr):
    """string IP to binary
    """
    (a, b, c, d) = [int(str) for str in ipaddr.split('.')]
    return (a << 24) + (b << 16) + (c << 8) + d


def bin_to_ip(ip_bin):
    """binary IP to string
    """
    return '%d.%d.%d.%d' % (ip_bin >> 24,
                            (ip_bin & 0x00FFFFFF) >> 16,
                            (ip_bin & 0x0000FFFF) >> 8,
                            ip_bin & 0x000000FF)


def netmask2masklen(netmask):
    """convert netmask to masklen
    """
    ip_bin = ip_to_bin(netmask)
    l = 0
    while ip_bin:
        l += ip_bin & 0x1
        ip_bin >>= 1
    return l


def masklen2netmask(masklen):
    """convert masklen to netmask
    """
    return bin_to_ip(0xffffffff ^ (0xffffffff >> masklen))


def ip_netmask_to_prefix(ip, netmask):
    ip_bin = ip_to_bin(ip) & ip_to_bin(netmask)
    return '%s/%s' % (bin_to_ip(ip_bin), netmask2masklen(netmask))
