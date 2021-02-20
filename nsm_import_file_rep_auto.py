"""
nsm_import_file_rep_auto.py v1.05; Author: Richie Yang; Last edited at 2021/2/20.
Compatible Platform list: McAfee NSM 9.1, CentOS 7.6-1810
Description: This script is made to remotely import file reputation CSV into NSM.
New Features: None
known Issues: None
"""

import requests
import logging
import traceback
import threading
import pprint
import json
import time
from datetime import datetime, timedelta
import sys
import re
import os
import nsm_api
import pprint
import loggia_lite

# You must initialize logging, otherwise you'll not see debug output.

loggia.Logging(filename='nsm_import_file_rep_auto')

# Real Script starts from here.
# nsm_ip = str(sys.argv[1])
# file_path = str(sys.argv[2])
# usr = str(sys.argv[3])
# pwd = str(sys.argv[4])

nsm_ip = '192.168.2.59'
file_path = 'test.csv'
usr = 'admin'
pwd = 'admin123'

nsm = nsm_api.NetworkSecurityManagerAPI(mcafee_nsm_ip=nsm_ip, username=usr, password=pwd)


def schedule_task_0():
    while True:
        logging.info("nsm_import_file_rep_auto.schedule_task_0 process: current schedule task is executed")
        dt = datetime.now() + timedelta(minutes=1)

        # To directly import blacklist up to McAfee NSM.
        nsm.import_custom_fingerprints(action='APPEND', file=file_path)
        logging.info("nsm_import_file_rep_auto.schedule_task_0 process: next execution time is %s" % dt)

        while datetime.now() < dt:
            time.sleep(1)


if __name__ == "__main__":
    """
    Something below can run at specific time everyday
    x = datetime.today()
    y = x.replace(day=x.day + 1, hour=1, minute=0, second=0, microsecond=0)
    delta_t = y - x
    secs = delta_t.seconds + 1
    """
    t0 = threading.Thread(target=schedule_task_0)
    t0.start()
