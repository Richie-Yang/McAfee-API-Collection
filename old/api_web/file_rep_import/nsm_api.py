"""
nsm_api.py v0.06; Author: Richie Yang; Last edited at 2020/12/04.
Compatible Platform list: CentOS 7.6-1810
Description: McAfee SM SDK API Library.
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
import base64


class NetworkSecurityManagerAPI:

    def __init__(self, mcafee_nsm_ip, username=str, password=str):
        self.server = mcafee_nsm_ip

        origin_combined_cred = "%s:%s" % (username, password)
        origin_cred_bytes = origin_combined_cred.encode('ascii')
        origin_cred_base64 = base64.b64encode(origin_cred_bytes)

        url = 'https://%s/sdkapi/session' % self.server
        hdr = {
            'NSM-SDK-API': origin_cred_base64,
            'Accept': 'application/vnd.nsm.v1.0+json',
            'Content-Type': 'application/json'
        }

        try:
            req = requests.get(url, verify=False, headers=hdr)
            rep = json.loads(req.text)
            logging.info("NetworkSecurityManagerAPI.__init__ process: response status is %s" % req.status_code)
            combined_cred = "%s:%s" % (rep['session'], rep['userId'])
            cred_bytes = combined_cred.encode('ascii')
            self.cred_base64 = base64.b64encode(cred_bytes)
            logging.info("NetworkSecurityManagerAPI.__init__ process: API key is %s" % self.cred_base64)

        except Exception as err:
            trace_output = traceback.print_exc()
            logging.error("NetworkSecurityManagerAPI.__init__ error traceback: %s" % str(trace_output))
            logging.error("NetworkSecurityManagerAPI.__init__ execution failed: %s" % str(err))
            sys.exit()

    def get_domain(self):
        url = 'https://%s/sdkapi/domain' % self.server
        hdr = {
            'NSM-SDK-API': self.cred_base64,
            'Accept': 'application/vnd.nsm.v1.0+json',
            'Content-Type': 'application/json'
        }

        try:
            req = requests.get(url, verify=False, headers=hdr)
            logging.info("NetworkSecurityManagerAPI.get_domain process: response status is %s" % req.status_code)
            rep = json.loads(req.text)
            logging.info("NetworkSecurityManagerAPI.get_domain process: response content is %s" % str(rep))
            return rep
        except Exception as err:
            trace_output = traceback.print_exc()
            logging.error("NetworkSecurityManagerAPI.get_domain error traceback: %s" % str(trace_output))
            logging.error("NetworkSecurityManagerAPI.get_domain execution failed: %s" % str(err))

    def get_alerts(self, alert_id=None, event_duration='LAST_12_HOURS'):
        url = 'https://%s/sdkapi/alerts' % self.server
        hdr = {
            'NSM-SDK-API': self.cred_base64,
            'Accept': 'application/vnd.nsm.v1.0+json',
            'Content-Type': 'application/json'
        }
        quy = {'alertid': str(alert_id), 'timeperiod': event_duration}

        try:
            req = requests.get(url, verify=False, headers=hdr, params=quy)
            logging.info("NetworkSecurityManagerAPI.get_alerts process: response status is %s" % req.status_code)
            rep = json.loads(req.text)
            logging.info("NetworkSecurityManagerAPI.get_alerts process: response content is %s" % str(rep))
            return rep
        except Exception as err:
            trace_output = traceback.print_exc()
            logging.error("NetworkSecurityManagerAPI.get_alerts error traceback: %s" % str(trace_output))
            logging.error("NetworkSecurityManagerAPI.get_alerts execution failed: %s" % str(err))

    def get_top_attacks(
            self, top_n_attacks=10, event_direction='ANY', event_duration='LAST_12_HOURS', event_filter=None):
        domain_id = str(self.get_domain())
        url = 'https://%s/sdkapi/domain/%s/threatexplorer/alerts/TopN/%s/direction/%s/duration/%s/attacks' \
              % (self.server, domain_id, top_n_attacks, event_direction, event_duration)
        hdr = {
            'NSM-SDK-API': self.cred_base64,
            'Accept': 'application/vnd.nsm.v1.0+json',
            'Content-Type': 'application/json'
        }

        try:
            req = requests.get(url, verify=False, headers=hdr)
            logging.info("NetworkSecurityManagerAPI.get_top_attacks process: response status is %s" % req.status_code)
            rep = json.loads(req.text)
            logging.info("NetworkSecurityManagerAPI.get_top_attacks process: response content is %s" % str(rep))
            return rep
        except Exception as err:
            trace_output = traceback.print_exc()
            logging.error("NetworkSecurityManagerAPI.get_top_attacks error traceback: %s" % str(trace_output))
            logging.error("NetworkSecurityManagerAPI.get_top_attacks execution failed: %s" % str(err))

    def import_custom_fingerprints(self, action='APPEND', file=None):
        if action != 'APPEND' and action != 'REPLACE':
            logging.warning("NetworkSecurityManagerAPI.import_custom_fingerprints process: "
                            "Please either input 'APPEND' or 'REPLACE'.")
            sys.exit()
        domain_rep = self.get_domain()
        domain_id = str(domain_rep['DomainDescriptor']['id'])
        url = 'https://%s/sdkapi/domain/%s/filereputation/customfingerprints' % (self.server, domain_id)
        hdr = {
            'NSM-SDK-API': self.cred_base64,
            'Accept': 'application/vnd.nsm.v1.0+json'
        }
        raw = {
            'Action': action
        }

        files = {
            'json': (None, json.dumps(raw), 'application/json'),
            'file': (os.path.basename(file), open(file, 'rb'), 'application/octet-stream')
        }

        try:
            req = requests.put(url, verify=False, headers=hdr, files=files)
            logging.info("NetworkSecurityManagerAPI.import_custom_fingerprints process: "
                         "response status is %s" % req.status_code)
            logging.info("NetworkSecurityManagerAPI.import_custom_fingerprints process: "
                         "response content is %s" % str(req.text))
        except Exception as err:
            trace_output = traceback.print_exc()
            logging.error("NetworkSecurityManagerAPI.import_custom_fingerprints error traceback: "
                          "%s" % str(trace_output))
            logging.error("NetworkSecurityManagerAPI.import_custom_fingerprints execution failed: "
                          "%s" % str(err))









