#SecurityOnion-AirGap

##Purpose
This project is meant to address managing a [Security Onion](https://security-onion-solutions.github.io/security-onion/) deployment inside an [air gapped](https://en.wikipedia.org/wiki/Air_gap_(networking)) network.

##Considerations
1. [Snort](https://snort.org/)
  - Snort rule updates. Security Onion comes shipped with an old ruleset from Emerging Threats. It is meant to be updated during sosetup and then by cron job.
  - Using other rulesets. When the Security Onion IDS is configured in offline mode, rule-update only looks for the emergingthreats ruleset.
2. [SQueRT](http://www.squertproject.org/)
  - ip2c updates. SQueRT only recognizes RFC1918 addresses by default. When sosetup is run, updates are pulled from the Regional Internet Registries and added to the securityonion_db.ip2c MySQL table. It is then updated by cron job.
3. [Bro](https://www.bro.org/)
  - GeoIP updates. Bro relies on GeoIP data files to assign country codes to its log entries. Security Onion ships with old versions of GeoIP.dat and GeoIPv6.dat. It does not have GeoIPCity.dat.
4. [Ubuntu](http://www.ubuntu.com/)
  - OS Updates. This should be an obvious consideration, but I will not be addressing it at this time. It is updated by apt-get/soup.
  - See [securityonion-utils/mirror_repo.py](https://github.com/SkiTheSlicer/securityonion-utils/blob/master/mirror_repo.py)

##Components
*Scripts were written in [Python 2.7.6](https://www.python.org/download/releases/2.7.6/).*

*Initial development was under Security Onion 12.04.5.3 and continued under 14.04.3.1.*

1. Online Downloader (securityonion_airgap_download.py)
  - Handles downloading and packaging updates for use by the updater script(s).
  - Requires [BeautifulSoup4](http://www.crummy.com/software/BeautifulSoup/bs4/download/) Python library.
  - Requires [requests](http://docs.python-requests.org/en/latest/user/install/#install) Python library (already included in Security Onion 14).

2. Offline Updater (securityonion_airgap_update.py)
  - Handles decompressing tarball from downloader and passes switches to respective sub-script updaters.
  
  1. SQueRT Updater (squert_ip2c_update.py).
    - Requires [mysql.connector](https://dev.mysql.com/downloads/connector/python/) Python library.
    - Requires MySQL root (SELECT, DROP, CREATE, INSERT, LOAD), but not OS root.
    - Master server only.
    - Based on ip2c.tcl and squert.sql in /var/www/so/squert/.scripts/
  
  2. Snort & Bro Updater (ids_offline_update.py).
    - Requires OS root to access priviledged directories.
    - Master server for Snort rules and GeoIP files.
    - Sensor server for GeoIP files.

##Example Download
    $ python securityonion_airgap_download.py -e *****@*****.com
*Email address has been sanitized.*
```
Output Dir: so-airgap-20160109-1757

[GeoIP]
Downloading GeoIP.dat.gz...
Decompressing GeoIP.dat.gz...
Downloading GeoIPv6.dat.gz...
Decompressing GeoIPv6.dat.gz...
Downloading GeoLiteCity.dat.gz...
Decompressing GeoLiteCity.dat.gz...
Downloading GeoLiteCityv6.dat.gz...
Decompressing GeoLiteCityv6.dat.gz...

[RIR]
Downloading delegated-afrinic-extended-latest...
Downloading delegated-afrinic-extended-latest.md5...
Downloading delegated-apnic-extended-latest...
Downloading delegated-apnic-extended-latest.md5...
Downloading delegated-arin-extended-latest...
Downloading delegated-arin-extended-latest.md5...
Downloading delegated-lacnic-extended-latest...
Downloading delegated-lacnic-extended-latest.md5...
Downloading delegated-ripencc-extended-latest...
Downloading delegated-ripencc-extended-latest.md5...
Checking MD5 for delegated-afrinic-extended-latest...
  MD5 OK
Checking MD5 for delegated-apnic-extended-latest...
  MD5 OK
Checking MD5 for delegated-arin-extended-latest...
  MD5 OK
Checking MD5 for delegated-lacnic-extended-latest...
  MD5 OK
Checking MD5 for delegated-ripencc-extended-latest...
  MD5 OK

[Snort Static]
Downloading community-rules.tar.gz...
Downloading md5s...
Downloading ip-filter.blf...
Downloading compromised-ips.txt...
Checking MD5 for community-rules.tar.gz...
  MD5 OK

[Snort ET Dynamic]
Downloading emerging.rules.tar.gz...
Downloading emerging.rules.tar.gz.md5...
Checking MD5 for emerging.rules.tar.gz...
  MD5 OK
Downloading emerging.rules.tar.gz...
Downloading emerging.rules.tar.gz.md5...
Checking MD5 for emerging.rules.tar.gz...
  MD5 OK

[Snort VRT Dynamic]
Snort.org E-mail: *****@*****.com
Password: 
Signed in successfully.
Downloading snortrules-snapshot-2962.tar.gz...
Downloading snortrules-snapshot-2976.tar.gz...
Downloading snortrules-snapshot-2980.tar.gz...
Downloading md5s...
Checking MD5 for snortrules-snapshot-2962.tar.gz...
  MD5 OK
Checking MD5 for snortrules-snapshot-2976.tar.gz...
  MD5 OK
Checking MD5 for snortrules-snapshot-2980.tar.gz...
  MD5 OK

[Final]
Compressing so-airgap-20160109-1757...
  MD5: be1581f3c9f58402978d1a2968624c88
```
    $ du -ch so-airgap-20160109-1757
```
40M	so-airgap-20160109-1757/GeoIP
20M	so-airgap-20160109-1757/RIR
384K	so-airgap-20160109-1757/Snort/VRT_Community
448K	so-airgap-20160109-1757/Snort/Blacklist
1.9M	so-airgap-20160109-1757/Snort/ET_GPL
1.8M	so-airgap-20160109-1757/Snort/ET_NonGPL
101M	so-airgap-20160109-1757/Snort/VRT_Registered
106M	so-airgap-20160109-1757/Snort
165M	so-airgap-20160109-1757
165M	total
```
    $ ls -lh so-airgap-20160109-1757.*
```
-rw-r--r-- 1 skitheslicer skitheslicer 131M Jan  9 18:02 so-airgap-20160109-1757.tar.gz
-rw-r--r-- 1 skitheslicer skitheslicer   63 Jan  9 18:02 so-airgap-20160109-1757.tar.gz.md5
```

##Example Update
    $ sudo dpkg -i mysql-connector-python_2.1.3-1ubuntu14.04_all.deb
```
Selecting previously unselected package mysql-connector-python.
(Reading database ... 152345 files and directories currently installed.)
Preparing to unpack mysql-connector-python_2.1.3-1ubuntu14.04_all.deb ...
Unpacking mysql-connector-python (2.1.3-1ubuntu14.04) ...
Setting up mysql-connector-python (2.1.3-1ubuntu14.04) ...
```
    $ python securityonion-airgap/securityonion_airgap_update.py -f so-airgap-20160209-2011.tar.gz
```
[MAIN: Setup]
Checking MD5 for so-airgap-20160209-2011.tar.gz...
  MD5 OK
Decompressing so-airgap-20160209-2011.tar.gz...
Base Dir: so-airgap-20160209-2011

[MAIN -> IDS: Blacklists, GeoIP, Rules]

[IDS: WARNING]
WARNING: black_list.rules not empty.
Press Enter to continue...

[IDS: Snort Blacklists]
Searching for Snort Blacklists in '/home/skitheslicer/so-airgap-20160209-2011/Snort/Blacklist'...
------	---------
NUMBER	BLACKLIST
------	---------
0	ET Blacklist
1	VRT Blacklist
2	Both VRT and ET Blacklists
Specify blacklist's number: 0
Appending compromised-ips.txt to '/etc/nsm/rules/black_list.rules'...

[IDS: Bro GeoIP DBs]
Searching for GeoIP DBs in '/home/skitheslicer/so-airgap-20160209-2011/GeoIP'...
------	------
NUMBER	OPTION
------	------
0	Only Update GeoIP Country DBs
1	Only Update GeoIP City DBs
2	Update GeoIP Country and City DBs
Specify update option's number: 0
Copying GeoIPv6.dat to '/usr/share/GeoIP/'...
Copying GeoIP.dat to '/usr/share/GeoIP/'...

[IDS: Snort Rules]
Searching for Snort Rules in '/home/skitheslicer/so-airgap-20160209-2011/Snort'...
------	-------
NUMBER	RULESET
------	-------
0	Emerging Threats GPL
1	Snort VRT Registered and Emerging Threats NoGPL
2	Snort VRT Community and Emerging Threats NoGPL
3	Snort VRT Registered, Community, and Emerging Threats NoGPL
Specify ruleset's number: 0
Copying emerging.rules.tar.gz to '/opt/emergingthreats/' and '/tmp/'...

[IDS: Final]
Please run 'rule-update' to complete the Snort update, if applicable.

[MAIN -> IP2C]

[IP2C: Parse RIR DBs]
Creating temp file /tmp/ip2c-results.csv from dir /home/skitheslicer/so-airgap-20160209-2011/RIR
Parsing delegated-arin-extended-latest to ip2c-results.csv...
  Added 57382 entries from delegated-arin-extended-latest
  Skipped 64989 entries in delegated-arin-extended-latest
Parsing delegated-afrinic-extended-latest to ip2c-results.csv...
  Added 3063 entries from delegated-afrinic-extended-latest
  Skipped 4486 entries in delegated-afrinic-extended-latest
Parsing delegated-ripencc-extended-latest to ip2c-results.csv...
  Added 59321 entries from delegated-ripencc-extended-latest
  Skipped 89315 entries in delegated-ripencc-extended-latest
Parsing delegated-lacnic-extended-latest to ip2c-results.csv...
  Added 11222 entries from delegated-lacnic-extended-latest
  Skipped 25426 entries in delegated-lacnic-extended-latest
Parsing delegated-apnic-extended-latest to ip2c-results.csv...
  Added 33271 entries from delegated-apnic-extended-latest
  Skipped 40553 entries in delegated-apnic-extended-latest

[IP2C: Update MySQL DB]
Updating table ip2c from /tmp/ip2c-results.csv
  Already Updated. Updating Again...
(Re)Creating table ip2c
  Dropped table ip2c
  (Re)Creation complete
Update complete

[IP2C: Update Validation]
Reading table ip2c
  Total Table Rows:  164262
  Unique Table Rows: 164262

Finished!
```
