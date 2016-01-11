#SecurityOnion-AirGap To-Do List
##securityonion_airgap_download.py
- [ ] Check for BeautifulSoup4 & requests before script runs.
  - Security Onion already includes requests.
##securityonion_airgap_update.py
- [ ] Add connection to ids*.py
- [ ] Confirm/Add sudo abilities.
- [ ] Add directory walk for input tarfile to update script
###squert_ip2c_update.py
- [ ] Add switch for read-only (no create_tmp_file, no update).
- [ ] Confirm still functional on its own.
- [ ] Add mysql.connector check before ip2c update script runs.
- [ ] Add check to only allow ip2c on master.
- [ ] Check if db exists, ie if sosetup run yet.
###ids_offline_update.py
- [ ] Create initial version.
- [ ] Add offline rule picker to updater
- [ ] Add check to only allow rules on master.