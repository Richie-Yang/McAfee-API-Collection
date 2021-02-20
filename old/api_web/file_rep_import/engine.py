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
import loggia

# You must initialize logging, otherwise you'll not see debug output.

loggia.Logging(filename='web_engine')

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
    t0 = threading.Thread(target=schedule_task_0)
    t0.start()
