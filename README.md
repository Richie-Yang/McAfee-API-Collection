# McAfee API Collection (mfe_api)
  This API Collection is bunch of scripts which were used to deal with limited functionalities from McAfee Product. They are mainly based on list import automation.And this Collection is intended for demostration only (PoC), running in production environment is strongly not recommended.
## >Current Functions
1. McAfee NSM (Network Security Manager)
A. IP blacklist import automation (via frirewall)
B. Domain blacklist import automation (via frirewall)
C. File hashes blacklist import automation (via Exception)
2. McAfee TIE (Threat Intelligence Exchange)
A. File hashes blacklist import automation (from file or list)
B. File hashes whitelist import automation (from file or list)

## >Prerequisites
1. OS (Operating System):
Windows 10 Pro (Recommended) or CentOS 7 (Recommended) or above

2. Language Enivronment:
Python 3.7 to 3.9 (Recommemded)

3. Modules depended on scripts:
certifi==2020.11.8
chardet==3.0.4
idna==2.10
requests==2.25.0
urllib3==1.26.2

[========]

[========]

[========]
## >How to setup environment (For CentOS 7)
##### 1. To download Python3.9 library
```shell
-wget https://www.python.org/ftp/python/3.9.0/Python-3.9.0.tgz
-tar xzf Python-3.9.0.tgz
```
##### 2. To install Python3.9 library

```shell
-cd Python-3.9.0
-./configure --enable-optimizations
-make altinstall
-cd
```
##### 3. Post-installation version check

```shell
-python3.9 --version
```
##### 4. To upgrade Python3.9 pip package

```shell
-/usr/local/bin/python3.9 -m pip install --upgrade pip

```
##### 5. To install script-dependent python packages
```shell
-cd mfe_api
-pip3.9 install -r requirements.txt
```
##### 6. Python scripts permission change
```shell
-chmod u+x nsm_import_file_rep_auto.py
-chmod u+x nsm_import_file_rep_man.py
-chmod u+x nsm_api.py
-chmod u+x loggia_lite.py
```
[========]
## >How to setup environment (For Windows 10)
##### 1. To download and install Python 3.9 library
Go to the link below to download Python 3.9:
[Python official website][1]
##### 2. To install script-dependent python packages
```shell
-cd mfe_api
-pip3 install requirements.txt
```

[========]

[========]

## >How to use the script - nsm_import_file_rep (For both OS)
##### 1. To change credentials in both python scripts

Change from this:

```python
# Real Script starts from here.
# nsm_ip = str(sys.argv[1])
# file_path = str(sys.argv[2])
# usr = str(sys.argv[3])
# pwd = str(sys.argv[4])

nsm_ip = '192.168.2.59'
file_path = 'test.csv'
usr = 'admin'
pwd = 'password'
```


to this:
```python
# Real Script starts from here.
nsm_ip = str(sys.argv[1])
file_path = str(sys.argv[2])
usr = str(sys.argv[3])
pwd = str(sys.argv[4])

# nsm_ip = '192.168.2.59'
# file_path = 'test.csv'
# usr = 'admin'
# pwd = 'password'
```
##### 2. How to ready your file hash list
Create one CSV file with the following table format, then save it as "test.csv" and upload to /mfe_api folder.

|   | A  | B  | C  | D  | E  |
| ------------ | ------------ | ------------ | ------------ | ------------ | ------------ |
| 1  | collectmail_notwo0a.pdf  |  1 | MD5  | 075c8160789eb0829488a4fc9b59ed6c  | description  |
| 2  | putty_v0.60.exe  |  1 | MD5  | acdac6399f73539f6c01b7670045eec7  | description  |



##### 3. How to fire up the python script
(CentOS 7):
```shell
-cd
-python3.9 mfe_api/nsm_import_file_rep_auto.py $NSM_IP$ $file_path$ $username$ $password$
-python3.9 mfe_api/nsm_import_file_rep_man.py $NSM_IP$ $file_path$ $username$ $password$
```
(Windows 10 Pro):
```shell
-cd
-python3 mfe_api/nsm_import_file_rep_auto.py $NSM_IP$ $file_path$ $username$ $password$
-python3 mfe_api/nsm_import_file_rep_man.py $NSM_IP$ $file_path$ $username$ $password$
```
If you were following this guide to step 2, then please change $file_path$ to point to test.csv.

[1]: https://www.python.org/downloads/ "Python official website"