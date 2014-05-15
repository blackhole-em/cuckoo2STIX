#!/usr/bin/env python2.7
import logging
import ConfigParser
import os

def setup_custom_logger(name):
    config = ConfigParser.ConfigParser()
    config.read('app.conf')
    logPath = config.get('logs', 'logPath')
    logFile = config.get('logs', 'logFile')
    if not os.path.exists(logPath):
        os.makedirs(logPath)
    logLevel = int(config.get('logs', 'logLevel'))
    lf = logging.Formatter(fmt='[%(asctime)s] [%(levelname)s] [%(module)s] %(funcName)s: %(message)s')

    ch = logging.StreamHandler()
    ch.setFormatter(lf)
    fh = logging.FileHandler(logPath + '/' + logFile)
    fh.setFormatter(lf)

    logger = logging.getLogger(name)
    logger.setLevel(logLevel)
    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger
