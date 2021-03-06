"""
nsm_import_file_rep_man.py v1.05; Author: Richie Yang; Last edited at 2021/2/20.
Compatible Platform list: McAfee NSM 9.1, CentOS 7.6-1810
Description: This script is made to remotely import file reputation CSV into NSM.
New Features: None
known Issues: None
"""

import requests
import logging
import traceback
import pprint
import json
import time
from datetime import datetime
import sys
import re
import os
import nsm_api
import pprint
import loggia_lite

# You must initialize logging, otherwise you'll not see debug output.

loggia_lite.Logging(filename='nsm_import_file_rep_man')

# Real Script starts from here.
# nsm_ip = str(sys.argv[1])
# blacklist_filename = str(sys.argv[2])
# usr = str(sys.argv[3])
# pwd = str(sys.argv[4])

nsm_ip = '192.168.2.59'
usr = 'admin'
pwd = 'admin123'
blacklist_filename = "blacklist_file_hash_for_nsm.csv"
dir_to_blacklist = os.path.dirname(os.path.abspath(__file__)) + "/import_lists/2_blacklist/%s" % blacklist_filename

'''
Initiating NSM API class with input NSM IP, admin account, and password.
'''

nsm = nsm_api.NetworkSecurityManagerAPI(mcafee_nsm_ip=nsm_ip, username=usr, password=pwd)

# To directly import blacklist up to McAfee NSM.

nsm.import_custom_fingerprints(action='APPEND', file=dir_to_blacklist)
