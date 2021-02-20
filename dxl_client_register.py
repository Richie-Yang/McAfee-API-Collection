"""
tie_set_file_rep_from_list.py v1.00; Author: Richie Yang; Last edited at 2021/2/20.
Compatible Platform list: Windows 10 20H2 and CentOS 7 (not tested)
Description: This script is made to help the user have easier DXL client registration process.
New Features: None
known Issues: None
"""

import traceback
import logging
import pprint
import time
import sys
import os
import loggia_lite

# You must initialize logging, otherwise you'll not see debug output.
loggia_lite.Logging(filename="dxl_client_register")

print("\nThis is the script which used to help you walking through DXL client registeration process.")
print("It's usually for one time only in order to generate associated config file.\n")

print("\nInstalling DXL Python client library...\n")
dir_to_dxlclient_lib = \
    os.path.join(os.path.dirname(__file__), 'lib/dxltieclient-python-dist/dxltieclient-python-dist-0.3.0/lib')
dxlclient_lib_install = 'pip3 install %s/%s' % (dir_to_dxlclient_lib, 'dxltieclient-0.3.0-py2.py3-none-any.whl')

dxlclient_lib_install_exec = os.system(dxlclient_lib_install)
logging.info(dxlclient_lib_install_exec)
print("\nDXL Python client library is installed.\n")

dxl_broker_ip_address = input("Please input DXL broker IP address:")
dxl_client_cn = input("Please input DXL client common name (CN):")
dxl_broker_username = input("Please input DXL broker username:")
dxl_broker_password = input("Please input DXL broker password:")

'''
Command Line Provisioning (Basic)
The OpenDXL Python Client's command line interface supports the provisionconfig operation which generates the 
information necessary for a client to connect to a DXL fabric (certificates, keys, and broker information).
As part of the provisioning process, a remote call will be made to a provisioning server (ePO or OpenDXL Broker) 
which contains the Certificate Authority (CA) that will sign the client's certificate.
NOTE: ePO-managed environments must have 4.0 (or newer) versions of DXL ePO extensions installed.

Here is an example usage of provisionconfig operation:
dxlclient provisionconfig config myserver client1
The parameters are as follows:

<<config>> is the directory to contain the results of the provisioning operation.
<<myserver>> is the host name or IP address of the server (ePO or OpenDXL Broker) that will be used to provision 
the client. 
<<client1>> is the value for the Common Name (CN) attribute stored in the subject of the client's certificate.
NOTE: If a non-standard port (not 8443) is being used for ePO or the management interface of the OpenDXL Broker, 
an additional "port" argument must be specified. For example -t 443 could be specified as part of the provision 
operation to connect to the server on port 443.

When prompted, provide credentials for the OpenDXL Broker Management Console or ePO 
(the ePO user must be an administrator):

Enter server username:
Enter server password:
On success, output similar to the following should be displayed:

INFO: Saving csr file to config/client.csr
INFO: Saving private key file to config/client.key
INFO: Saving DXL config file to config/dxlclient.config
INFO: Saving ca bundle file to config/ca-bundle.crt
INFO: Saving client certificate file to config/client.crt
As an alternative to prompting, the username and password values can be specified via command line options:

dxlclient provisionconfig config myserver client1 -u myuser -p mypass
See the Command Line Provisioning (Advanced) section for advanced provisionconfig operation options.
'''
print("\nRegistering with user-designated DXL broker...\n")
dxl_client_register = 'dxlclient provisionconfig config %s %s -u %s -p %s' % (
    dxl_broker_ip_address,
    dxl_client_cn,
    dxl_broker_username,
    dxl_broker_password
)
dxl_client_register_execution = os.system(dxl_client_register)
logging.info(dxl_client_register_execution)
print("\nuser-designated DXL broker registration finished.\n")
