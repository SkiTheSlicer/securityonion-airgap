#!/usr/bin/python
# 20151223  https://github.com/SkiTheSlicer
# 20151227  Started adding OS Walk, MD5 Check, TAR support. Not yet functional.
# 20151229  Added TAR support. Required input DIR to be raw (because of DIRs named like \20151229).

def parse_arguments():
  from datetime import datetime
  import argparse
  import os
  datetime_now = datetime.now().strftime('%Y%m%d-%H%M')
  parser = argparse.ArgumentParser(
    prog='securityonion-airgap-download.py',
    description='Download updates for tools within Security Onion.',
    epilog='Created by SkiTheSlicer (https://github.com/SkiTheSlicer)')
    #formatter_class=argparse.RawTextHelpFormatter)
  parser.add_argument('-e', '--snort-email',
                      nargs='?',
                      help='If supplied, download VRT Registered Rulesets with specified snort.org email address.')#,
                      #action='store_true')
  parser.add_argument('-d', '--output-dir',
                      nargs='?', default="so-airgap-"+datetime_now,
                      help='If supplied, download files to specific directory.')#,
                      #action='store_true')
  return parser.parse_args()

def decompress_gunzip_files(directory_to_search):
  import os
  import gzip
  for item in os.listdir(directory_to_search):
    if not os.path.isdir(os.path.join(directory_to_search, item)) and item.endswith('.gz') and not item.endswith('.tar.gz'):
      print "Decompressing " + item + "..."
      with gzip.open(os.path.join(directory_to_search, item), 'rb') as f:
        file_content = f.read()
      path_to_store = os.path.join(directory_to_search, item[:-3])
      with open(path_to_store, 'wb') as f:
          f.write(file_content)
      os.remove(os.path.join(directory_to_search, item))

def extract_md5s(directory_to_search):
  import os
  for item in os.listdir(directory_to_search):
    item_path = os.path.join(directory_to_search, item)
    if not os.path.isdir(item_path) and item == 'md5s':
      with open(item_path, 'r') as f:
        for line in f:
          with open(os.path.join(directory_to_search, ".".join([line.strip().split(' ')[1], 'md5'])), 'wb') as output_file:
            output_file.write(line.strip())
      os.remove(item_path)

def compare_md5s(directory_to_search):
  import os
  import re
  md5pattern = re.compile("(^|[^0-9a-f])([0-9a-f]{32})([^0-9a-f]|$)")
  for item in os.listdir(directory_to_search):
    item_path = os.path.join(directory_to_search, item)
    if not os.path.isdir(item_path) and item.endswith('.md5') and os.path.isfile(item_path[:-4]):
      print "Checking MD5 for " + item[:-4] + "..."
      with open(item_path, 'r') as f:
        #expected_md5 = f.readline().strip().split(' ')[0]
        expected_md5 = re.search(md5pattern, f.readline()).group(2)
        if not re.match(md5pattern, expected_md5):
          print "  ERROR: Invalid MD5 of " + expected_md5
      calculated_md5 = calculate_md5(item_path[:-4])
      if expected_md5 != calculated_md5:
        print "  " + calculated_md5 + ' != ' + expected_md5
      else:
        print "  MD5 OK"

def calculate_md5(file_to_hash):
  # Ref: http://pythoncentral.io/hashing-files-with-python/
  import hashlib
  BLOCKSIZE = 65536
  hasher = hashlib.md5()
  #hashlib.sha512(open(fn).read()[8:]).hexdigest()
  with open(file_to_hash, 'rb') as binaryfile:
    bufferedfile = binaryfile.read(BLOCKSIZE)
    while len(bufferedfile) > 0:
      hasher.update(bufferedfile)
      bufferedfile = binaryfile.read(BLOCKSIZE)
  return hasher.hexdigest()

def scrape_snort(page_to_scrape, vendor_name):
  import requests
  from bs4 import BeautifulSoup
  import re
  results = "error"
  r = requests.get(page_to_scrape)
  if [[ r.status_code == requests.codes.ok ]]:
    soup = BeautifulSoup(r.text, 'html.parser')
    if vendor_name == "ET":
      anchors = soup.find_all('a', href=re.compile('snort\-[0-9.]{5}/'))
     #Slicing. http://stackoverflow.com/questions/509211/explain-pythons-slice-notation
      results = anchors[-1].text[:-1]
    elif vendor_name == "VRT":
      #open("r.html", 'wb').write(r.text.encode('utf-8')) #testing
      results = []
      divs = soup.find_all('div', class_="col-md-12 disabled", text=re.compile("snortrules-snapshot-[0-9]{4}.tar.gz"))
      for idx, val in enumerate(divs):
        #print idx, val.text.strip()
        results.append(val.text.strip())
      results = sorted(set(results))
  else:
    print r.status_code
  return results

def requests_download_file(url_to_download, local_folder_name):
  import requests
  import os
  r = requests.get(url_to_download, stream=True)
  if r.status_code == 200:
    file_name = r.url.split('?')[0].split('/')[-1]
    file_path = os.path.join(local_folder_name, file_name)
    if not os.path.exists(local_folder_name):
      os.makedirs(local_folder_name)
    print "Downloading " + file_name + "..."
    with open(file_path, 'wb') as binaryfile:
      for chunk in r.iter_content(1024):
        binaryfile.write(chunk)
  else:
    print str(r.status_code) + ": " + url_to_download

def requests_login_download_file(url_array_to_download, local_folder_name, login_page, user_email):
  import requests
  from bs4 import BeautifulSoup
  import getpass
  import os
  import sys
  s = requests.Session()
 # Set cookie
  r = s.get(login_page)
  #open("login_page.html", 'wb').write(r.text.encode('utf-8')) #testing
  soup = BeautifulSoup(r.content, "html.parser")
  form = soup.find("form", action="/users/sign_in")
 # Get CSRF (Cross-site request forgery)
  csrf = form.find('input', attrs={'name': 'authenticity_token'}).get('value')
  #print "Token: " + csrf
 # Login
  status = "Error"
  while status != "Signed in successfully.":
    print "Snort.org E-mail: " + user_email
    user_pass = getpass.getpass()
    payload = {
      'user[email]': user_email,
      'user[password]': user_pass,
      'authenticity_token': csrf
    }
    #headers = {'User-Agent': 'Mozilla/5.0'}
    #r = s.post(login_page, headers=headers, data=payload)
    r = s.post(login_page, data=payload)
    #open("login_response.html", 'wb').write(r.text.encode('utf-8')) #testing
    soup = BeautifulSoup(r.content, "html.parser")
    try:
     # LoginSuccess
      status = soup.find('div', attrs={"data-alert": "alert"}).p.text
      print status
    except AttributeError:
     # LoginFail
      status = soup.find('div', id="error_messages").p.text
      print status
      #sys.exit(1)
 # Download Files
  for url_to_download in url_array_to_download:
    r = s.get(url_to_download, stream=True)
    if r.status_code == 200:
      file_name = url_to_download.split('/')[-1]
      file_path = os.path.join(local_folder_name, file_name)
      if not os.path.exists(local_folder_name):
        os.makedirs(local_folder_name)
      print "Downloading " + file_name + "..."
      with open(file_path, 'wb') as binaryfile:
        for chunk in r.iter_content(1024):
          binaryfile.write(chunk)
    else:
      print str(r.status_code) + ": " + url_to_download

def create_tarfile(directory_to_compress):
  import os
  import tarfile
  output_file = ".".join([directory_to_compress, "tar", "gz"])
  if os.path.exists(output_file):
    print "ERROR: " + os.path.basename(output_file) + " already exists. Skipping."
  else:
    print "Compressing " + os.path.basename(directory_to_compress) + "..."
    with tarfile.open(output_file, "w:gz") as tar:
      tar.add(directory_to_compress, arcname=os.path.basename(directory_to_compress))
    tar_md5 = calculate_md5(output_file)
    with open(".".join([output_file, 'md5']), 'wb') as md5:
      md5.write(tar_md5 + " " + os.path.basename(output_file))
    print "  MD5: " + tar_md5

def main():
  import os
  args = parse_arguments()
  if not os.path.exists(args.output_dir):
    os.makedirs(args.output_dir)
  print "Output Dir: " + args.output_dir
 # Download GeoIP information.
  print "\n[GeoIP]"
  urls_geoip = [
    "http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz",
    "http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz",
    "http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz",
    "http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz"
  ]
  for url in urls_geoip:
    requests_download_file(url, os.path.join(args.output_dir, "GeoIP"))
    decompress_gunzip_files(os.path.join(args.output_dir, "GeoIP"))
 # Download Regional Internet Registry information.
  print "\n[RIR]"
  urls_rir = [
    "http://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
    "http://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest.md5",
    "http://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest",
    "http://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest.md5",
    "http://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "http://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest.md5",
    "http://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "http://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest.md5",
    "http://ftp.ripe.net/ripe/stats/delegated-ripencc-extended-latest",
    "http://ftp.ripe.net/ripe/stats/delegated-ripencc-extended-latest.md5"
  ]
  for url in urls_rir:
    requests_download_file(url, os.path.join(args.output_dir, "RIR"))
  compare_md5s(os.path.join(args.output_dir, "RIR"))
 # Download statically-defined Snort rulesets.
  print "\n[Snort Static]"
  urls_snort_static = [
    ["VRT_Community", "https://www.snort.org/downloads/community/community-rules.tar.gz"],
    ["VRT_Community", "https://www.snort.org/downloads/community/md5s"],
    ["Blacklist", "http://labs.snort.org/feeds/ip-filter.blf"],
    ["Blacklist", "http://rules.emergingthreats.net/blockrules/compromised-ips.txt"]
  ]#["VRT_Community", "https://www.snort.org/downloads/community/opensource.tar.gz"],
  for url in urls_snort_static:
   requests_download_file(url[1], os.path.join(args.output_dir, "Snort", url[0]))
   #compare_md5s(os.path.join(args.output_dir, "Snort", url[0]))
  extract_md5s(os.path.join(args.output_dir, "Snort", "VRT_Community"))
  compare_md5s(os.path.join(args.output_dir, "Snort", "VRT_Community"))
 # Download dynamically-defined Snort rulesets.
  print "\n[Snort ET Dynamic]"
  urls_snort_dynamic_et = [
    ["ET_GPL", "http://rules.emergingthreats.net/open", "emerging.rules.tar.gz"],
    ["ET_GPL", "http://rules.emergingthreats.net/open", "emerging.rules.tar.gz.md5"],
    ["ET_NonGPL", "http://rules.emergingthreats.net/open-nogpl", "emerging.rules.tar.gz"],
    ["ET_NonGPL", "http://rules.emergingthreats.net/open-nogpl", "emerging.rules.tar.gz.md5"]
  ]
  current_et_version = scrape_snort("http://rules.emergingthreats.net/open", "ET")
  for url in urls_snort_dynamic_et:
    #current_et_version = scrape_snort(url[1], "ET")
    final_url = "/".join([url[1],current_et_version,url[2]])
    requests_download_file(final_url, os.path.join(args.output_dir, "Snort", url[0]))
    compare_md5s(os.path.join(args.output_dir, "Snort", url[0]))
  if args.snort_email:
    print "\n[Snort VRT Dynamic]"
   # Scrape for all rule file paths
    current_vrt_versions = scrape_snort("https://www.snort.org/downloads/", "VRT")
    current_vrt_versions.append("md5s")
    for idx, val in enumerate(current_vrt_versions):
      current_vrt_versions[idx] = "/".join(["https://www.snort.org/downloads/registered", val])
   # Download rules
    requests_login_download_file(current_vrt_versions, os.path.join(args.output_dir, "Snort", "VRT_Registered"), "https://www.snort.org/users/sign_in", args.snort_email)
    extract_md5s(os.path.join(args.output_dir, "Snort", "VRT_Registered"))
    compare_md5s(os.path.join(args.output_dir, "Snort", "VRT_Registered"))
  print "\n[Final]"
  create_tarfile(args.output_dir)

if __name__ == "__main__":
  main()