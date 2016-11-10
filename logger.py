import os
import sys
import logging
from logging.handlers import TimedRotatingFileHandler

from const import LOG_FILE

log = logging.getLogger(__name__)


def init_logger(args=None):
    global log
    if args and args.daemon:
        handler = LcTimedRotatingFileHandler(LOG_FILE, when='midnight')
    else:
        handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s T%(thread)d '
        '%(levelname)s %(module)s.%(funcName)s.%(lineno)d: %(message)s')
    handler.setFormatter(formatter)

    log.setLevel(logging.DEBUG)
    log.addHandler(handler)

    stat_worker_log = logging.getLogger("stat_worker")
    stat_worker_log.addHandler(handler)
    stat_worker_log.setLevel(logging.INFO)


class LcTimedRotatingFileHandler(TimedRotatingFileHandler):

    def __init__(self, *args, **kwargs):
        TimedRotatingFileHandler.__init__(self, *args, **kwargs)
        # redirect stderr to log file
        os.dup2(self.stream.fileno(), sys.stderr.fileno())

    def doRollover(self):
        TimedRotatingFileHandler.doRollover(self)
        # redirect stderr to log file
        os.dup2(self.stream.fileno(), sys.stderr.fileno())
