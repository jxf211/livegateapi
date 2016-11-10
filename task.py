# -*- coding: utf-8 -*-
from logger import log
import threading
import gevent
from Queue import Queue
from const import MAX_THREAD, QUEUE_TIME_OUT, FLUSH_LIMIT, MAC_ENTRY_COOKIE,\
    MAC_ENTRY_TABLE, PING_SLEEP_TIME
from utils import call_system_sh
import traceback
import commands
import time
import copy

task_transfer_queue = Queue()
cmd_waiting_queues = []
cmd_waiting_cons = []


class CmdTask(threading.Thread):
    """System Command Task worker thread
    """
    def __init__(self, que):
        super(self.__class__, self).__init__()
        self.daemon = True
        self.que = que
        global cmd_waiting_queues, cmd_waiting_cons
        self.queue = cmd_waiting_queues[que]
        self.con = cmd_waiting_cons[que]

    def run(self):
        log.info('cmd task%d starts working ...' % self.que)

        while True:
            with self.con:
                while True:  # try to get a task
                    if len(self.queue):
                        task = self.queue[0]
                        del self.queue[0]
                        break
                    self.con.wait()
            key, message, ret_queue, ignore = task

            log.info('%s: get a message {key: %s, message: %s, ignore:'
                     ' %s}, from queue%d. '
                     'current queue length: %d' % (self.name,
                                                   key,
                                                   message,
                                                   ignore,
                                                   self.que,
                                                   len(self.queue)))
            if ignore:
                rc, output = 0, ""
            else:
                if isinstance(message[0], list):
                    for args in message:
                        rc, output = call_system_sh(args)
                        if rc != 0:
                            break
                else:
                    rc, output = call_system_sh(message)

            if ret_queue:
                ret_queue.put((rc, output))


class TransferThread(threading.Thread):
    def __init__(self):
        super(self.__class__, self).__init__()
        self.daemon = True

    def run(self):
        self.setName('X00')
        log.info('task transfer thread starts working ...')

        global cmd_waiting_queues, cmd_waiting_cons

        while True:
            index, message_key, message, ret_queue = task_transfer_queue.get()

            with cmd_waiting_cons[index]:
                queue_len = len(cmd_waiting_queues[index])
                for i in xrange(queue_len):
                    key_in, message_in, ret, ignore = \
                        cmd_waiting_queues[index][i]
                    if message_key == key_in and not ignore:
                        log.info('key: %s message: %s which in queue%d will '
                                 'be ignore, queue length: '
                                 '%d' % (key_in,
                                         message_in,
                                         index,
                                         len(cmd_waiting_queues[index])))
                        cmd_waiting_queues[index][i] = (key_in,
                                                        message_in,
                                                        ret,
                                                        True)

                log.info('message %s will be put into vport queue%d, queue '
                         'length: %d' % (message,
                                         index,
                                         len(cmd_waiting_queues[index])))
                cmd_waiting_queues[index].append((message_key,
                                                  message,
                                                  ret_queue,
                                                  False))
                cmd_waiting_cons[index].notify()


def create_cmd_tasks():
    global cmd_waiting_queues, cmd_waiting_cons
    TransferThread().start()
    for i in xrange(MAX_THREAD):
        cmd_waiting_queues.append([])
        cmd_waiting_cons.append(threading.Condition())
        CmdTask(i).start()


def router_hash(router_id):
    return int(router_id) % MAX_THREAD


def cmd_waiting_queues_put(hash_key,
                           hash_func,
                           message_key,
                           message,
                           ret_queue=None):
    u"""
    参数：
    hash_key: 用于做哈希的关键字 如: router_id
    hash_func: 哈希函数 如:router_hash
    message_key: 消息的唯一标识 如: ('update', 'vpn', '370093')
    message: 消息内容，可以为嵌套队列 如:
    [['/usr/local/livegate/script/router.sh', 'flush', 'vpn', '370093'],
     ['/usr/local/livegate/script/router.sh', 'add', 'vpn', '370093',
      u'zzvpn', '1', u'192.168.39.115', u'26.26.26.0',
      u'255.255.255.0', u'192.168.39.111', u'22.22.22.0', u'255.255.255.0',
      u'zhouqi']]
    ret_queue: 线程用于接收返回消息的队列 Queue()
    返回值：
    无
    """

    index = hash_func(hash_key)
    global task_transfer_queue
    task_transfer_queue.put((index, message_key, message, ret_queue))


def read_response_handle(ret_list):
    u"""
    参数：
    ret_list: 接收特定返回值的list
    """
    def wrapper(rc, output):
        if rc == 0:
            ret_list.append(output)
    return wrapper


class PseudoGeventQueue(Queue, object):
    u""" 不能直接使用gevent.queue.Queue用户协程和线程之间的通信 """
    def __init__(self):
        super(self.__class__, self).__init__()

    def get_nb(self, timeout=QUEUE_TIME_OUT):
        wait = 0.001
        while self.empty():
            gevent.sleep(wait)
            if wait < 1:
                wait *= 2
            timeout -= wait
            if timeout <= 0:
                raise Exception('Timeout')
        return self.get(block=False)


def cmd_response_get(ret_queue, handle_func=None, ret_num=1):
    u"""
    参数：
    ret_queue: 线程用于接收返回消息的队列 PseudoGeventQueue()
    handle_func: 需要对消息进行特殊处理时
    ret_num: put的次数，多次put需要接收多个返回信息
    返回值：
    返回字符串表示出错信息，当为""时，表明执行正确。多个错误会由','隔开
    """
    assert isinstance(ret_queue, PseudoGeventQueue)

    response = []
    for i in xrange(ret_num):
        try:
            rc, output = ret_queue.get_nb(timeout=QUEUE_TIME_OUT)
            log.info("get a response (%d, %s)" % (rc, output))
            if handle_func:
                handle_func(rc, output)
            response.append((rc, output))
        except Exception as e:
            log.error('ret_num: %d, Exception: %s' % (ret_num, e))
            log.error('%s' % traceback.format_exc())
            # system command return code, 1 means error
            response.append((1, str(e)))
            break
    tmp = (output for rc, output in response if rc != 0)
    return ','.join(tmp)


class PingTask(threading.Thread):
    """Ping check worker thread
    """
    tunnel_ip_lock = threading.Lock()
    tunnel_ip_queue = {}

    def __init__(self):
        super(self.__class__, self).__init__()
        self.daemon = True

    @classmethod
    def add_peer_ip(cls, ip):
        with cls.tunnel_ip_lock:
            cls.tunnel_ip_queue[ip] = 0

    @classmethod
    def del_peer_ip(cls, ip):
        with cls.tunnel_ip_lock:
            if ip in cls.tunnel_ip_queue:
                del cls.tunnel_ip_queue[ip]

    def run(self):
        log.info('ping task starts working ...')
        while True:
            flush_flag = 0

            with self.__class__.tunnel_ip_lock:
                ip_queue = copy.deepcopy(self.__class__.tunnel_ip_queue)

            for k, v in ip_queue.iteritems():
                cmd = "ping %s -c 3 -q" % k
                rc, output = commands.getstatusoutput(cmd)
                if rc:
                    v += 1
                    with self.__class__.tunnel_ip_lock:
                        if k in self.__class__.tunnel_ip_queue:
                            self.__class__.tunnel_ip_queue[k] = v
                    if v == FLUSH_LIMIT:
                        flush_flag = 1
                else:
                    with self.__class__.tunnel_ip_lock:
                        if k in self.__class__.tunnel_ip_queue:
                            self.__class__.tunnel_ip_queue[k] = 0

            if flush_flag:
                log.error("ping gre end point failed, flush mac table.")
                cmd = "ovs-ofctl del-flows tunbr cookie=%x/-1,table=%d" % (
                    MAC_ENTRY_COOKIE, MAC_ENTRY_TABLE)
                rc, output = commands.getstatusoutput(cmd)
                log.info("command: %s, rc: %s, output: %s" % (cmd,
                                                              str(rc),
                                                              output))
                cmd = "ovs-appctl fdb/flush tunbr"
                rc, output = commands.getstatusoutput(cmd)
                log.info("command: %s, rc: %s, output: %s" % (cmd,
                                                              str(rc),
                                                              output))

            cmd = "ovs-ofctl dump-aggregate tunbr cookie=0x1/-1 | awk -F\"=\""\
                " '{print $5}'"
            rc, output = commands.getstatusoutput(cmd)
            if rc:
                log.error("dump drop flow failed [%s]" % cmd)
            else:
                ret = int(output)
                if not ret:
                    log.error("no drop flow [%s]" % cmd)
                    cmd = "ovs-ofctl del-flows tunbr table=0,cookie=0x0/-1"
                    rc, output = commands.getstatusoutput(cmd)
                    log.info("command: %s, rc: %s, output: %s" % (cmd,
                                                                  str(rc),
                                                                  output))
                    cmd = "ovs-ofctl add-flow tunbr cookie=0x1,table=0,"\
                        "priority=1,actions=drop"
                    rc, output = commands.getstatusoutput(cmd)
                    log.info("command: %s, rc: %s, output: %s" % (cmd,
                                                                  str(rc),
                                                                  output))

            time.sleep(PING_SLEEP_TIME)
