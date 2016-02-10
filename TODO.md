#SecurityOnion-AirGap To-Do List

##securityonion_airgap_download.py
- [ ] Check for BeautifulSoup4 & requests before script runs.
  - Security Onion already includes requests.
- [ ] Add VRT Paid Ruleset.
- [ ] Add mysql.connector download.

##securityonion_airgap_update.py
- [x] Add connection to ids*.py.
- [x] Confirm/Add sudo abilities.
- [ ] Add directory walk for input tarfile to update script.
- [ ] Add mysql.connector check that can be skipped.

###squert_ip2c_update.py
- [ ] Add switch for read-only (no create_tmp_file, no update).
- [ ] Confirm still functional on its own.
- [x] Add mysql.connector check before ip2c update script runs.
- [ ] Add check to only allow ip2c on master.
- [x] Check if db exists, ie if sosetup run yet.

###ids_offline_update.py
- [x] Create initial version.
- [x] Add offline rule picker to updater.
- [ ] Add check to only allow rules on master.
- [ ] Add update validation see [securityonion-utils/TSHOOT.md](https://github.com/SkiTheSlicer/securityonion-utils/blob/master/TSHOOT.md).
- [ ] Add numbered option to skip blacklist (or overwrite instead of append).
- [ ] Add VRT Paid Ruleset check
- [ ] Add answer file capabilites for geoip, blacklist, ruleset selection options.
