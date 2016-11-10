#! /usr/bin/python
from gevent.wsgi import WSGIServer
import argparse
import os
import signal
import sys
import traceback

from app import app
import logger
from lg_sysconfig import init_system
from task import create_cmd_tasks, PingTask
from utils import get_ip_address

# TODO: set server options and daemonize


def daemonize(stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
    """
    do the UNIX double-fork magic, see Stevens' "Advanced
    Programming in the UNIX Environment" for details (ISBN 0201563177)
    http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
    """
    try:
        pid = os.fork()
        if pid > 0:
            # exit first parent
            sys.exit(0)
    except OSError, e:
        sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)

    # decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)

    # do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # exit from second parent
            sys.exit(0)
    except OSError, e:
        sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)

    # redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    si = file(stdin, 'r')
    so = file(stdout, 'a+')
    se = file(stderr, 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())


def sigterm_handler(signal, frame):
    sys.exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--daemon", help="run in background",
                        action="store_true")

    parser.add_argument("-i", "--init", help="init system",
                        action="store_true")
    args = parser.parse_args()
    if args.daemon and os.getppid() != 1:
        daemonize()

    signal.signal(signal.SIGTERM, sigterm_handler)

    logger.init_logger(args)
    logger.log.info('Launching LiveGate API Stack (a.k.a. NSP Talker) ...')

    init_system(args.init)

    create_cmd_tasks()
    PingTask().start()

    local_ctrl_ip = get_ip_address("nspbr0")
    try:
        logger.log.info('Gevent approaching ...')
        server = WSGIServer((local_ctrl_ip, 20009), app)
        server.serve_forever()
    except Exception as e:
        logger.log.error('Exception: %s' % e)
        logger.log.error('%s' % traceback.format_exc())
        sys.exit(1)
