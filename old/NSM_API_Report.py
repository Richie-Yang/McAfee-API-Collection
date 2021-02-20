# NSM_API_Report.py v0.3; Author: Richie Yang; Last edited at 2020/10/04.
# Compatible Platform list: McAfee NSM 9.1, 9.2
# Description: This script is made to remotely call McAfee NSM to report the details based on queried events.
# New Features: v3.0(1.New function get_alerts added, 2.Report function can now display as html on browser)
# known Issues: v3.0(Function get_alerts unable to filter)

import requests
import logging
import pprint
import json
import time
import sys
import re
import os
import webbrowser
import base64
import json2html

# You must initialize logging, otherwise you'll not see debug output.

logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True


class NSM_API():
    def __init__(self, McAfee_NSM_IP):
        self.server = McAfee_NSM_IP

        cred = username + ':' + password
        cred_bytes = cred.encode('ascii')
        cred_base64 = base64.b64encode(cred_bytes)

        url = 'https://' + self.server + '/sdkapi/session'
        quy = {'NSM-SDK-API': cred_base64, 'Accept': 'application/vnd.nsm.v1.0+json', 'Content-Type': 'application/json'}

        try:
            req = requests.get(url, verify=False, headers=quy)
            rep = json.loads(req.text)
            self.session = rep['session']
            self.userid = rep['userId']
            print(rep)

            cred = self.session + ':' + self.userid
            cred_bytes = cred.encode('ascii')
            self.cred_base64 = base64.b64encode(cred_bytes)

        except Exception as err:
            print("Error in generating auth token --> " + str(err))
            sys.exit()

    def get_domain(self):
        url = 'https://' + self.server + '/sdkapi/domain'
        quy = {'NSM-SDK-API': self.cred_base64, 'Accept': 'application/vnd.nsm.v1.0+json', 'Content-Type': 'application/json'}
        req = requests.get(url, verify=False, headers=quy)
        print(req.status_code)
        print(req.headers)
        print(quy)
        print(req.text)
        rep = json.loads(req.text)
        self.domain_id = str(rep['DomainDescriptor']['id'])
        print(self.domain_id)
        return str(req.text)

    def get_alerts(self, Alert_ID = None, Event_Duration = 'LAST_12_HOURS'):
        self.alrt_id = str(Alert_ID)
        self.evt_dur = Event_Duration

        url = 'https://' + self.server + '/sdkapi/alerts?' + 'alertid=' + self.alrt_id + '&timeperiod=' + self.evt_dur
        quy = {'NSM-SDK-API': self.cred_base64, 'Accept': 'application/vnd.nsm.v1.0+json', 'Content-Type': 'application/json'}
        req = requests.get(url, verify=False, headers=quy)
        print(req.status_code)
        print(req.headers)
        print(quy)
        print(req.text)
        rep = json.loads(req.text)
        rep_html = json2html.json2html.convert(rep)
        with open('Alerts_Detail_Report.html', 'w') as f:
            f.write(str(rep_html))
            webbrowser.open_new_tab('Alerts_Detail_Report.html')
        return str(req.text)


    def get_top_attacks(self, Top_N_Attacks = 10, Event_Direction = 'ANY', Event_Duration = 'LAST_12_HOURS', Event_Filter = None):
        self.top_atk = str(Top_N_Attacks)
        self.evt_dir = Event_Direction
        self.evt_dur = Event_Duration
        self.evt_flt = Event_Filter

        url = 'https://' + self.server + '/sdkapi/domain/' + self.domain_id + '/threatexplorer/alerts/TopN/' + self.top_atk + \
              '/direction/' + self.evt_dir + '/duration/' + self.evt_dur + '/attacks'
        quy = {'NSM-SDK-API': self.cred_base64, 'Accept': 'application/vnd.nsm.v1.0+json', 'Content-Type': 'application/json'}
        req = requests.get(url, verify=False, headers=quy)
        print(req.status_code)
        print(req.headers)
        print(quy)
        print(req.text)
        rep = json.loads(req.text)
        rep_html = json2html.json2html.convert(rep)
        with open('Top_' + self.top_atk + '_Attacks_Report.html', 'w') as f:
            f.write(str(rep_html))
            webbrowser.open_new_tab('Top_' + self.top_atk + '_Attacks_Report.html')
        return str(req.text)


# Real Script starts from here.
#fmc_ip = str(sys.argv[1])
#dt_ip = str(sys.argv[2])

nsm_ip = '192.168.2.59'
dt_ip = '10.10.10.10'

# Username and password.
username = "admin"
password = "admin123"

nsm = NSM_API(nsm_ip)
nsm.get_domain()
nsm.get_alerts(6846099775777609566)
