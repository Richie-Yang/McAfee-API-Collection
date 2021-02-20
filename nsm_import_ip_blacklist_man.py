"""
nsm_import_ip_blacklist_man.py v1.00; Author: Richie Yang; Last edited at 2021/2/20.
Compatible Platform list: McAfee NSM 9.1 and 10.1, Windows 10 20H2
Description: This script is made to remotely import IP blacklist CSV into NSM.
New Features: None
known Issues: If maximum object is hit within one firewall rule, no new firewall rule will be created.
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

loggia_lite.Logging(filename='nsm_import_ip_blacklist_man')

# Real Script starts from here.
'''
nsm_ip = str(sys.argv[1])
policy_name = str(sys.argv[2])
usr = str(sys.argv[3])
pwd = str(sys.argv[4])
'''

nsm_ip = '192.168.2.59'
policy_name = 'Firewall Policy'
usr = 'admin'
pwd = 'admin123'
whitelist_filename = "whitelist_ip.txt"
blacklist_filename = "blacklist_ip.txt"
dir_to_whitelist = os.path.dirname(os.path.abspath(__file__)) + "/import_lists/1_whitelist/%s" % whitelist_filename
dir_to_blacklist = os.path.dirname(os.path.abspath(__file__)) + "/import_lists/2_blacklist/%s" % blacklist_filename

'''
To read CSV file to retrieve IP blacklist, and also calculate the length of the list.
'''

blacklist_ip_list = []

with open(dir_to_blacklist) as file:
    contents = file.read()
    file_as_list = contents.splitlines()

    for line in file_as_list:
        if re.match(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line):
            blacklist_ip_list.append(line)

blacklist_ip_list_len = len(blacklist_ip_list)

# pprint.pprint(blacklist_ip_list_len)

'''
Initiating NSM API class with input NSM IP, admin account, and password.
'''

nsm = nsm_api.NetworkSecurityManagerAPI(mcafee_nsm_ip=nsm_ip, username=usr, password=pwd)

'''
Creating new rule objects based on list of the CSV file. Once the creation process is successful, 
NSM will response with createdResourceId, which will later used in blacklist_ip_profile.
'''

blacklist_ip_processed_list = []
rule_object_id = ''

for i in range(blacklist_ip_list_len):
    rule_object_data_1 = nsm.add_rule_object(
        add_rule_object_type='HostIPv4',
        rule_object_visible_to_child_opt=True,
        rule_object_desc='api-generated',
        rule_object_name=str(blacklist_ip_list[i]),
        rule_object_data={
            'hostIPv4AddressList': [
                str(blacklist_ip_list[i])
            ]},
        rule_object_type='HOST_IPV_4'
    )
    try:
        rule_object_id = str(rule_object_data_1["createdResourceId"])

    except KeyError as err:
        trace_output = traceback.print_exc()
        logging.error("nsm_import_ip_blacklist_man error traceback: %s" % str(trace_output))
        logging.error("nsm_import_ip_blacklist_man execution failed: %s" % str(err))

        rule_object_data_2 = nsm.get_rule_objects_from_domain(rule_object_type='HostIPv4')
        rule_object_data_len_2 = len(rule_object_data_2['RuleObjDef'])

        for z in range(rule_object_data_len_2):
            if rule_object_data_2['RuleObjDef'][z]['HostIPv4']['hostIPv4AddressList'][0] == \
                    str(blacklist_ip_list[i]) and \
                    rule_object_data_2['RuleObjDef'][z]['description'] == 'api-generated':
                rule_object_id = rule_object_data_2['RuleObjDef'][z]['ruleobjId']

    finally:
        blacklist_ip_profile = {
            'Name': str(blacklist_ip_list[i]),
            'RuleObjectId': str(rule_object_id),
            'RuleObjectType': 'HOST_IPV_4'
        }
        blacklist_ip_processed_list.append(blacklist_ip_profile)

logging.debug("nsm_import_ip_blacklist_man process: pending blacklist ip profiles are %s"
              % str(blacklist_ip_processed_list))
# pprint.pprint(str(blacklist_ip_processed_list))

'''
  In order to update firewall policy, it's necessary to retrieve firewall policy ID first.
  At the same time, some data coming from get_firewall_policies_from_domain are needed to 
store into variables for later use.
  Then we have to retrieve much more detail from specific firewall policy ID, such as MemberDetails,
  so update_firewall_policy can be made successfully.
'''

firewall_policy_summary_data = nsm.get_firewall_polices_from_domain()

logging.debug("nsm_import_ip_blacklist_man process: firewall policy summary data is %s"
              % str(firewall_policy_summary_data))

firewall_policy_summary_data_obj = firewall_policy_summary_data['FirewallPoliciesForDomainResponseList']
firewall_policy_summary_data_len = len(firewall_policy_summary_data_obj)

for x in range(firewall_policy_summary_data_len):
    if firewall_policy_summary_data_obj[x]['policyName'] == policy_name:

        firewall_policy_name = firewall_policy_summary_data_obj[x]['policyName']
        firewall_policy_visible_to_child_opt = firewall_policy_summary_data_obj[x]['visibleToChild']
        firewall_policy_desc = firewall_policy_summary_data_obj[x]['description']
        firewall_policy_type = firewall_policy_summary_data_obj[x]['policyType']
        firewall_policy_version = firewall_policy_summary_data_obj[x]['policyVersion']

        firewall_policy_detail_data = nsm.get_firewall_policy_detail(
            firewall_policy_id=firewall_policy_summary_data_obj[x]['policyId']
        )

        logging.debug("nsm_import_ip_blacklist_man process: firewall policy detail data is %s"
                      % str(firewall_policy_summary_data))
        # pprint.pprint(firewall_policy_detail_data)

        firewall_policy_id = firewall_policy_detail_data['FirewallPolicyId']
        firewall_policy_domain_id = firewall_policy_detail_data['DomainId']
        last_firewall_policy_modified_time = firewall_policy_detail_data['LastModifiedTime']
        firewall_policy_editable_opt = firewall_policy_detail_data['IsEditable']
        last_firewall_policy_modified_user = firewall_policy_detail_data['LastModifiedUser']
        firewall_policy_member_rule_list = firewall_policy_detail_data['MemberDetails']

        logging.debug("nsm_import_ip_blacklist_man process: pending firewall policy rules are %s"
                      % str(firewall_policy_member_rule_list))
        # pprint.pprint(firewall_policy_member_rule_list)

        firewall_policy_member_rule_list_len = \
            len(firewall_policy_member_rule_list['MemberRuleList'][0]['SourceAddressObjectList'])

        for y in range(blacklist_ip_list_len):
            matched_count = 0
            for z in range(firewall_policy_member_rule_list_len):
                if str(blacklist_ip_list[y]) not in \
                        firewall_policy_member_rule_list['MemberRuleList'][0]['SourceAddressObjectList'][z]['Name']:
                    matched_count += 1
                elif str(blacklist_ip_list[y]) in \
                        firewall_policy_member_rule_list['MemberRuleList'][0]['SourceAddressObjectList'][z]['Name']:
                    matched_count -= 1

            if matched_count == firewall_policy_member_rule_list_len:
                firewall_policy_member_rule_list['MemberRuleList'][0]['SourceAddressObjectList'].append(
                    blacklist_ip_processed_list[y]
                )

        if firewall_policy_member_rule_list['MemberRuleList'][0]['SourceAddressObjectList'][0]['Name'] == "Any":
            firewall_policy_member_rule_list['MemberRuleList'][0]['SourceAddressObjectList'].pop(0)

        logging.debug("nsm_import_ip_blacklist_man process: processed firewall policy rules are %s"
                      % str(firewall_policy_member_rule_list))
        # pprint.pprint(firewall_policy_member_rule_list)

        nsm.update_firewall_policy(
            firewall_policy_id=firewall_policy_id,
            firewall_policy_name=firewall_policy_name,
            firewall_policy_domain_id=firewall_policy_domain_id,
            firewall_policy_visible_to_child_opt=firewall_policy_visible_to_child_opt,
            firewall_policy_desc=firewall_policy_desc,
            last_firewall_policy_modified_time=last_firewall_policy_modified_time,
            firewall_policy_editable_opt=firewall_policy_editable_opt,
            firewall_policy_type=firewall_policy_type,
            firewall_policy_version=firewall_policy_version,
            last_firewall_policy_modified_user=last_firewall_policy_modified_user,
            firewall_policy_member_rule_list=firewall_policy_member_rule_list
        )
        break
