"""
nsm_api.py v0.15; Author: Richie Yang; Last edited at 2021/2/19.
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

    def get_rule_objects_from_domain(self, rule_object_type=str):
        domain_rep = self.get_domain()
        domain_id = str(domain_rep['DomainDescriptor']['id'])

        url = 'https://%s/sdkapi/domain/%s/ruleobject?type=%s' % (self.server, domain_id, rule_object_type)
        hdr = {
            'NSM-SDK-API': self.cred_base64,
            'Accept': 'application/vnd.nsm.v1.0+json',
            'Content-Type': 'application/json'
        }

        try:
            req = requests.get(url, verify=False, headers=hdr)
            logging.info("NetworkSecurityManagerAPI.get_rule_objects_from_domain process: response status is "
                         "%s" % req.status_code)
            rep = json.loads(req.text)
            logging.info("NetworkSecurityManagerAPI.get_rule_objects_from_domain process: response content is "
                         "%s" % str(rep))
            return rep
        except Exception as err:
            trace_output = traceback.print_exc()
            logging.error("NetworkSecurityManagerAPI.get_rule_objects_from_domain error traceback: "
                          "%s" % str(trace_output))
            logging.error("NetworkSecurityManagerAPI.get_rule_objects_from_domain execution failed: "
                          "%s" % str(err))

    def add_rule_object(
            self, add_rule_object_type=str, rule_object_visible_to_child_opt=bool, rule_object_desc=str,
            rule_object_name=str, rule_object_data=dict, rule_object_type=str
    ):
        domain_rep = self.get_domain()
        domain_id = str(domain_rep['DomainDescriptor']['id'])
        url = 'https://%s/sdkapi/ruleobject' % self.server

        hdr = {
            'NSM-SDK-API': self.cred_base64,
            'Accept': 'application/vnd.nsm.v1.0+json',
            'Content-Type': 'application/json'
        }
        raw = {
            'RuleObjDef': {
                'domain': domain_id,
                'visibleToChild': rule_object_visible_to_child_opt,
                'description': rule_object_desc,
                'name': rule_object_name,
                'ruleobjType': rule_object_type,
            }
        }
        if add_rule_object_type == "HostIPv4":
            raw['RuleObjDef']['HostIPv4'] = rule_object_data
        elif add_rule_object_type == "HOST_DNS_NAME":
            raw['RuleObjDef']['HostDNSName'] = rule_object_data

        try:
            req = requests.post(url, verify=False, headers=hdr, data=json.dumps(raw))
            logging.info("NetworkSecurityManagerAPI.add_rule_object process: response status is "
                         "%s" % req.status_code)
            rep = json.loads(req.text)
            logging.info("NetworkSecurityManagerAPI.add_rule_object process: response content is "
                         "%s" % req.text)
            return rep
        except Exception as err:
            trace_output = traceback.print_exc()
            logging.error("NetworkSecurityManagerAPI.add_rule_object error traceback: %s" % str(trace_output))
            logging.error("NetworkSecurityManagerAPI.add_rule_object execution failed: %s" % str(err))

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

    def get_firewall_polices_from_domain(self):
        domain_rep = self.get_domain()
        domain_id = str(domain_rep['DomainDescriptor']['id'])
        url = 'https://%s/sdkapi/domain/%s/firewallpolicy' % (self.server, domain_id)
        hdr = {
            'NSM-SDK-API': self.cred_base64,
            'Accept': 'application/vnd.nsm.v1.0+json',
            'Content-Type': 'application/json'
        }
        try:
            req = requests.get(url, verify=False, headers=hdr)
            logging.info("NetworkSecurityManagerAPI.get_firewall_policy_from_domain process: "
                         "response status is %s" % req.status_code)
            rep = json.loads(req.text)
            logging.info("NetworkSecurityManagerAPI.get_firewall_policy_from_domain process: "
                         "response content is %s" % str(rep))
            return rep
        except Exception as err:
            trace_output = traceback.print_exc()
            logging.error("NetworkSecurityManagerAPI.get_firewall_policy_from_domain error traceback: "
                          "%s" % str(trace_output))
            logging.error("NetworkSecurityManagerAPI.get_firewall_policy_from_domain execution failed: "
                          "%s" % str(err))

    def get_firewall_policy_detail(self, firewall_policy_id=int):
        url = 'https://%s/sdkapi/firewallpolicy/%s' % (self.server, firewall_policy_id)
        hdr = {
            'NSM-SDK-API': self.cred_base64,
            'Accept': 'application/vnd.nsm.v1.0+json',
            'Content-Type': 'application/json'
        }
        try:
            req = requests.get(url, verify=False, headers=hdr)
            logging.info("NetworkSecurityManagerAPI.get_firewall_policy_detail process: "
                         "response status is %s" % req.status_code)
            rep = json.loads(req.text)
            logging.info("NetworkSecurityManagerAPI.get_firewall_policy_detail process: "
                         "response content is %s" % str(rep))
            return rep
        except Exception as err:
            trace_output = traceback.print_exc()
            logging.error("NetworkSecurityManagerAPI.get_firewall_policy_detail error traceback: "
                          "%s" % str(trace_output))
            logging.error("NetworkSecurityManagerAPI.get_firewall_policy_detail execution failed: "
                          "%s" % str(err))

    def update_firewall_policy(
            self, firewall_policy_id=int, firewall_policy_name=str, firewall_policy_domain_id=int,
            firewall_policy_visible_to_child_opt=bool, firewall_policy_desc=str, last_firewall_policy_modified_time=str,
            firewall_policy_editable_opt=bool, firewall_policy_type=str, firewall_policy_version=int,
            last_firewall_policy_modified_user=str, firewall_policy_member_rule_list=dict
    ):
        url = 'https://%s/sdkapi/firewallpolicy/%s' % (self.server, firewall_policy_id)
        hdr = {
            'NSM-SDK-API': self.cred_base64,
            'Accept': 'application/vnd.nsm.v1.0+json',
            'Content-Type': 'application/json'
        }
        raw = {
            'FirewallPolicyId': firewall_policy_id,
            'Name': firewall_policy_name,
            'DomainId': firewall_policy_domain_id,
            "VisibleToChild": firewall_policy_visible_to_child_opt,
            "Description": firewall_policy_desc,
            "LastModifiedTime": last_firewall_policy_modified_time,
            "IsEditable": firewall_policy_editable_opt,
            "PolicyType": firewall_policy_type,
            "PolicyVersion": firewall_policy_version,
            "LastModifiedUser": last_firewall_policy_modified_user,
            "MemberDetails": firewall_policy_member_rule_list
        }
        try:
            req = requests.put(url, verify=False, headers=hdr, data=json.dumps(raw))
            logging.info("NetworkSecurityManagerAPI.update_firewall_policy process: response status is "
                         "%s" % req.status_code)
            logging.info("NetworkSecurityManagerAPI.update_firewall_policy process: response content is "
                         "%s" % req.text)
        except Exception as err:
            trace_output = traceback.print_exc()
            logging.error("NetworkSecurityManagerAPI.update_firewall_policy error traceback: %s" % str(trace_output))
            logging.error("NetworkSecurityManagerAPI.update_firewall_policy execution failed: %s" % str(err))

