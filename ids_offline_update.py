#!/usr/bin/python
# Created by https://github.com/SkiTheSlicer

def parse_arguments():
  import argparse
  parser = argparse.ArgumentParser(
    prog='ids_offline_update.py',
    description='Update Snort\'s ruleset(s) and Bro\'s GeoIP files in Security Onion.',
    epilog='Created by SkiTheSlicer (https://github.com/SkiTheSlicer)')
  parser.add_argument('-b', '--blacklists',
                      action='store_true',
                      help='Perform Snort blacklist updates only.')
  parser.add_argument('-g', '--geoip',
                      action='store_true',
                      help='Perform Bro GeoIP updates only.')
  parser.add_argument('-r', '--rules',
                      action='store_true',
                      help='Perform Snort rule updates only.')
  parser.add_argument('-B', '--blacklists-dir',
                      nargs='?', default='.',
                      help='Specifies directory containing Snort blacklist updates.')
  parser.add_argument('-G', '--geoip-dir',
                      nargs='?', default='.',
                      help='Specifies directory containing GeoIP updates.')
  parser.add_argument('-R', '--rules-dir',
                      nargs='?', default='.',
                      help='Specifies directory containing Snort rule updates.')
  parser.add_argument('-I', '--ignore-warnings',
                      action='store_true',
                      help='If specified, ignore warnings and continue.')
  return parser.parse_args()

def check_for_warnings():
  import os
  import subprocess
  warn_msgs = []
  if not os.path.exists('/var/log/sosetup.log') and not os.path.exists('/var/log/nsm/sosetup.log'):
    warn_msgs.append('WARNING: No sosetup.log; running sosetup may overwrite these changes.')
  existing_dbs = subprocess.Popen(['mysql', '-u', 'root', '-e', 'SHOW DATABASES'], stdout=subprocess.PIPE)
  if not 'securityonion_db' in existing_dbs.stdout.read():
    warn_msgs.append('WARNING: No securityonion_db; not master or sosetup not run.')
  try:
    with open('/etc/nsm/rules/black_list.rules', 'r') as f:
      for i, l in enumerate(f):
        pass
      i = i + 1
    if i > 0:
      warn_msgs.append('WARNING: black_list.rules not empty.')
  except:
    warn_msgs.append('WARNING: black_list.rules file doesn\'t exist.')
  return warn_msgs

def update_geoip_dbs(directory_to_walk):
  import os
  import subprocess
  geoip_country_paths = []
  geoip_city_paths = []
  print 'Searching for GeoIP DBs in \'' + os.path.abspath(directory_to_walk) + '\'...'
  for root, dirs, files in os.walk(directory_to_walk):
    for file in files:
      if file == 'GeoIP.dat':
        geoip_country_paths.append(os.path.abspath(os.path.join(root, file)))
      elif file == 'GeoIPv6.dat':
        geoip_country_paths.append(os.path.abspath(os.path.join(root, file)))
      elif file == 'GeoLiteCity.dat':
        geoip_city_paths.append(os.path.abspath(os.path.join(root, file)))
      elif file == 'GeoLiteCityv6.dat':
        geoip_city_paths.append(os.path.abspath(os.path.join(root, file)))
  selection_names = []
  selection_paths = []
  if len(geoip_country_paths) > 0:
    selection_names.append('Only Update GeoIP Country DBs')
    selection_paths.append(geoip_country_paths)
  if len(geoip_city_paths) > 0:
    selection_names.append('Only Update GeoIP City DBs')
    selection_paths.append(geoip_city_paths)
  if len(geoip_country_paths) > 0 and len(geoip_city_paths) > 0:
    selection_names.append('Update GeoIP Country and City DBs')
    selection_paths.append(geoip_country_paths + geoip_city_paths)
  print '------\t------\nNUMBER\tOPTION\n------\t------'
  for idx, val in enumerate(selection_names):
    print str(idx) + '\t' + val
  selection = input('Specify update option\'s number: ')
  try:
    for path in selection_paths[selection]:
      print 'Copying ' + os.path.basename(path) + ' to \'/usr/share/GeoIP/\'...'
      subprocess.call(['sudo', 'cp', path, '/usr/share/GeoIP/'])
      if 'GeoLiteCity.dat' in path:
        print '  Creating symlink...'
        subprocess.call(['sudo', 'ln', '-s', '/usr/share/GeoIP/GeoLiteCity.dat', '/usr/share/GeoIP/GeoIPCity.dat'])
      elif 'GeoLiteCityv6.dat' in path:
        print '  Creating symlink...'
        subprocess.call(['sudo', 'ln', '-s', '/usr/share/GeoIP/GeoLiteCityv6.dat', '/usr/share/GeoIP/GeoIPCityv6.dat'])
  except IndexError:
    print 'ERROR: Invalid Selection.'

def update_snort_rules(directory_to_walk):
  import subprocess
  import re
  import os
  import tarfile
  #snort_version = subprocess.call('snort -V 2>&1 | grep Version | egrep -o "([0-9]\.){3}([0-9])"')
  snort_version = subprocess.Popen(['snort', '-V'], stderr=subprocess.PIPE)
  snort_version = re.search("Version (([0-9]\.){3})([0-9])", snort_version.stderr.read())
  snort_version = snort_version.group(1) + snort_version.group(3)
  #print snort_version
  vrt_reg_pattern = re.compile("^snortrules-snapshot-[0-9]{4}\.tar\.gz$")
  rules_available = []
  rule_paths = []
  print 'Searching for Snort Rules in \'' + os.path.abspath(directory_to_walk) + '\'...'
  for root, dirs, files in os.walk(directory_to_walk):
    for file in files:
      if file == 'emerging.rules.tar.gz':
        et_path = os.path.abspath(os.path.join(root, file))
        with tarfile.open(et_path, 'r:gz') as tar_file:
          tar_contents = tar_file.getnames()
        if any("-open-nogpl.txt" in filename for filename in tar_contents):
          rules_available.append('ET NoGPL')
          rule_paths.append(et_path)
        elif any("-open.txt" in filename for filename in tar_contents):
          rules_available.append('ET GPL')
          rule_paths.append(et_path)
      elif file == 'community-rules.tar.gz':
          rules_available.append('VRT Community')
          rule_paths.append(os.path.abspath(os.path.join(root, file)))
      elif re.match(vrt_reg_pattern, file):
        if snort_version.replace('.','') in file:
          rules_available.append('VRT Registered')
          rule_paths.append(os.path.abspath(os.path.join(root, file)))
  selection_names = []
  selection_paths = []
  if 'ET GPL' in rules_available:
    selection_names.append('Emerging Threats GPL')
    selection_paths.append([rule_paths[rules_available.index('ET GPL')]])
  if 'ET NoGPL' in rules_available and 'VRT Registered' in rules_available:
    selection_names.append('Snort VRT Registered and Emerging Threats NoGPL')
    selection_paths.append([rule_paths[rules_available.index('ET NoGPL')],rule_paths[rules_available.index('VRT Registered')]])
  if 'ET NoGPL' in rules_available and 'VRT Community' in rules_available:
    selection_names.append('Snort VRT Community and Emerging Threats NoGPL')
    selection_paths.append([rule_paths[rules_available.index('ET NoGPL')],rule_paths[rules_available.index('VRT Community')]])
  if 'ET NoGPL' in rules_available and 'VRT Registered' in rules_available and 'VRT Community' in rules_available:
    selection_names.append('Snort VRT Registered, Community, and Emerging Threats NoGPL')
    selection_paths.append([rule_paths[rules_available.index('ET NoGPL')],rule_paths[rules_available.index('VRT Registered')],rule_paths[rules_available.index('VRT Community')]])
  print '------\t-------\nNUMBER\tRULESET\n------\t-------'
  for idx, val in enumerate(selection_names):
    print str(idx) + '\t' + val
  selection = input('Specify ruleset\'s number: ')
  try:
    for path in selection_paths[selection]:
      print 'Copying ' + os.path.basename(path) + ' to \'/opt/emergingthreats/\' and \'/tmp/\'...'
      subprocess.call(['sudo', 'cp', path, '/opt/emergingthreats/'])
      subprocess.call(['sudo', 'cp', path, '/tmp/'])
  except IndexError:
    print 'ERROR: Invalid Selection.'

def update_snort_blacklists(directory_to_walk):
  import os
  import subprocess
  import re
  from datetime import datetime
  datetime_now = datetime.now().strftime('%Y%m%d-%H%M')
  lists_available = []
  list_paths = []
  print 'Searching for Snort Blacklists in \'' + os.path.abspath(directory_to_walk) + '\'...'
  for root, dirs, files in os.walk(directory_to_walk):
    for file in files:
      if file == 'ip-filter.blf':
        vrt_path = os.path.abspath(os.path.join(root, file))
        lists_available.append('VRT Blacklist')
        list_paths.append([vrt_path])
      elif file == 'compromised-ips.txt':
        et_path = os.path.abspath(os.path.join(root, file))
        lists_available.append('ET Blacklist')
        list_paths.append([et_path])
  if 'VRT Blacklist' in lists_available and 'ET Blacklist' in lists_available:
    lists_available.append('Both VRT and ET Blacklists')
    list_paths.append([vrt_path, et_path])
  print '------\t---------\nNUMBER\tBLACKLIST\n------\t---------'
  for idx, val in enumerate(lists_available):
    print str(idx) + '\t' + val
  selection = input('Specify blacklist\'s number: ')
  try:
    for path in list_paths[selection]:
      print 'Appending ' + os.path.basename(path) + ' to \'/etc/nsm/rules/black_list.rules\'...'
      with open(path, 'r') as new_blacklist:
        for line in new_blacklist:
          blacklist_cmd_p1 = subprocess.Popen(['echo', line.strip() + '\t#' + datetime_now + '\t' + os.path.basename(path)], stdout=subprocess.PIPE)
          blacklist_cmd_p2 = subprocess.Popen(['sudo', 'tee', '-a', '/etc/nsm/rules/black_list.rules'], stdin=blacklist_cmd_p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)          
      #blacklist_cmd = 'for line in $(cat ' + path + '); do echo $line\t#' + datetime_now + '\t' + os.path.basename(path) + '| sudo tee -a /etc/nsm/rules/black_list.rules; done'
      #print 'TEST: ' + blacklist_cmd
      #import shlex
      #subprocess.Popen([shlex.split(blacklist_cmd)])
  except IndexError:
    print 'ERROR: Invalid Selection.'

def main():
  import os
  import sys
  args = parse_arguments()
  warn_msgs = check_for_warnings()
  if len(warn_msgs) > 0:
    print "\n[IDS: WARNING]"
    for warn_msg in warn_msgs:
      print warn_msg
    if not args.ignore_warnings:
      raw_input("Press Enter to continue...")
  if not os.path.exists(args.blacklists_dir):
    print 'ERROR: ' + args.blacklists_dir + ' doesn\'t exist. Exitting.'
    sys.exit(1)
  elif not os.path.isdir(args.blacklists_dir):
    print 'ERROR: ' + args.blacklists_dir + ' is invalid directory. Exitting.'
    sys.exit(1)
  if not os.path.exists(args.geoip_dir):
    print 'ERROR: ' + args.geoip_dir + ' doesn\'t exist. Exitting.'
    sys.exit(1)
  elif not os.path.isdir(args.geoip_dir):
    print 'ERROR: ' + args.geoip_dir + ' is invalid directory. Exitting.'
    sys.exit(1)
  if not os.path.exists(args.rules_dir):
    print 'ERROR: ' + args.rules_dir + ' doesn\'t exist. Exitting.'
    sys.exit(1)
  elif not os.path.isdir(args.rules_dir):
    print 'ERROR: ' + args.rules_dir + ' is invalid directory. Exitting.'
    sys.exit(1)
  if args.blacklists:
    print "\n[IDS: Snort Blacklists]"
    update_snort_blacklists(args.blacklists_dir)
  elif args.geoip:
    print "\n[IDS: Bro GeoIP DBs]"
    update_geoip_dbs(args.geoip_dir)
  elif args.rules:
    print "\n[IDS: Snort Rules]"
    update_snort_rules(args.rules_dir)
  else:
    print "\n[IDS: Snort Blacklists]"
    update_snort_blacklists(args.blacklists_dir)
    print "\n[IDS: Bro GeoIP DBs]"
    update_geoip_dbs(args.geoip_dir)
    print "\n[IDS: Snort Rules]"
    update_snort_rules(args.rules_dir)
  print '\n[IDS: Final]\nPlease run \'rule-update\' to complete the Snort update, if applicable.'

if __name__ == "__main__":
  main()
