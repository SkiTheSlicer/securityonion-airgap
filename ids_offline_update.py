#!/usr/bin/python

def parse_arguments():
  import argparse
  #import os
  #import sys
  parser = argparse.ArgumentParser(
    prog='ids_offline_update.py',
    description='Update Snort\'s ruleset(s) and Bro\'s GeoIP files in Security Onion.',
    epilog='Created by SkiTheSlicer (https://github.com/SkiTheSlicer)')
    #formatter_class=argparse.RawTextHelpFormatter)
  parser.add_argument('-g', '--geoip',
                      action='store_true',
                      help='Perform Bro GeoIP updates only.')
  parser.add_argument('-G', '--geoip-dir',
                      nargs='?', default='.',
                      help='Specifies directory containing GeoIP updates.')
#Make this a like rule-picker, instead?
#  parser.add_argument('-c', '--country-only',
#                      action='store_true',
#                      help='Do not stage GeoIPCity.dat file(s).')
  parser.add_argument('-r', '--rules',
                      action='store_true',
                      help='Perform Snort rule updates only.')
  parser.add_argument('-R', '--rules-dir',
                      nargs='?', default='.',
                      help='Specifies directory containing Snort Rule updates.')
  return parser.parse_args()

def main():
  import os
  import subprocess
  import re
  import tarfile
  args = parse_arguments()
  if args.geoip:
    geoip_country_paths = []
    geoip_city_paths = []
    for root, dirs, files in os.walk(args.geoip_dir):
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
    print 'NUMBER\tOPTION\n------\t------'
    for idx, val in enumerate(selection_names):
      print str(idx) + '\t' + val
    selection = input('Specify update option\'s number: ')
    try:
      print 'You selected: ' + str(selection_paths[selection])
    except IndexError:
      print 'ERROR: Invalid Selection.'
    for path in selection_paths[selection]:
      subprocess.call(['sudo', 'cp', path, '/usr/share/GeoIP/'])
      if 'GeoLiteCity.dat' in path:
        subprocess.call(['sudo', 'ln', '-s', '/usr/share/GeoIP/GeoLiteCity.dat', '/usr/share/GeoIP/GeoIPCity.dat'])
      elif 'GeoLiteCityv6.dat' in path:
        subprocess.call(['sudo', 'ln', '-s', '/usr/share/GeoIP/GeoLiteCityv6.dat', '/usr/share/GeoIP/GeoIPCityv6.dat'])
  elif args.rules:
    #listdir; if blacklist exists, ask about blacklist; if ET exists, ask about ET; if VRT exists, ask about VRT. Mirror this off sosetup choices?
    #md5pattern = re.compile("(^|[^0-9a-f])([0-9a-f]{32})([^0-9a-f]|$)")
    #snort_version = subprocess.call('snort -V 2>&1 | grep Version | egrep -o "([0-9]\.){3}([0-9])"')
    snort_version = subprocess.Popen(['snort', '-V'], stderr=subprocess.PIPE)
    snort_version = re.search("Version (([0-9]\.){3})([0-9])", snort_version.stderr.read())
    #snort_version = re.search("Version (([0-9]\.){3})([0-9])", subprocess.Popen(['snort', '-V'], stderr=subprocess.PIPE).stderr.read())
    snort_version = snort_version.group(1) + snort_version.group(3)
    #print snort_version
    #et_pattern = re.compile("^emerging\.rules\.tar\.gz$")
    vrt_reg_pattern = re.compile("^snortrules-snapshot-[0-9]{4}\.tar\.gz$")
    #vrt_com_pattern = re.compile("^community-rules\.tar\.gz$")
    rules_available = []
    rule_paths = []
    for root, dirs, files in os.walk(args.rules_dir):
      for file in files:
        #if re.match(et_pattern, file):
        if file == 'emerging.rules.tar.gz':
          et_path = os.path.abspath(os.path.join(root, file))
          with tarfile.open(et_path, 'r:gz') as tar_file:
            #tar_contents = tar_file.list(verbose=False)
            tar_contents = tar_file.getnames()
          #print tar_contents
          if any("-open-nogpl.txt" in filename for filename in tar_contents):
            #et_nogpl_path = et_path
            rules_available.append('ET NoGPL')
            rule_paths.append(et_path)
            #print 'et_nogpl_path: ' + et_nogpl_path
          elif any("-open.txt" in filename for filename in tar_contents):
            #et_gpl_path = et_path
            rules_available.append('ET GPL')
            rule_paths.append(et_path)
            #print 'et_gpl_path: ' + et_gpl_path
        #elif re.match(vrt_com_pattern, file):
        elif file == 'community-rules.tar.gz':
            #vrt_com_path = os.path.abspath(os.path.join(root, file))
            rules_available.append('VRT Community')
            rule_paths.append(os.path.abspath(os.path.join(root, file)))
            #print 'vrt_com_path: ' + vrt_com_path
        elif re.match(vrt_reg_pattern, file):
          if snort_version.replace('.','') in file:
            #vrt_reg_path = os.path.abspath(os.path.join(root, file))
            rules_available.append('VRT Registered')
            rule_paths.append(os.path.abspath(os.path.join(root, file)))
            #print 'vrt_reg_path: ' + vrt_reg_path
    #print rules_available
    selection_names = []
    selection_paths = []
  #  for idx, val in enumerate(rules_available):
  #    if 'ET GPL' in val:
  #      selection_names.append('Emerging Threats GPL')
  #      selection_paths.append([rule_paths[idx]])
  #    if 'ET GPL' in val:
  #      selection_names.append('Emerging Threats GPL')
  #      selection_paths.append([rule_paths[idx]])
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
    print 'NUMBER\tRULESET\n------\t-------'
#    for idx, val in enumerate(rules_available):
    for idx, val in enumerate(selection_names):
      print str(idx) + '\t' + val
    selection = input('Specify ruleset\'s number: ')
    try:
#      print 'You selected: ' + rule_paths[selection]
      print 'You selected: ' + str(selection_paths[selection])
    except IndexError:
      print 'ERROR: Invalid Selection.'
    #print rule_paths
    ##for path in rule_paths:
    #for path in selection_paths:
    #  #subprocess.call(['sudo', 'cp', path, '/opt/emergingthreats/'])
    #  subprocess.call(['cp', path, '/tmp/'])
  else:
    print 'Do geoip'
    print 'Do rules'
    #subprocess.call(['sudo', 'ifconfig', 'eth0'])
    #subprocess.call(['sudo', 'ifconfig', 'eth0'])

if __name__ == "__main__":
  main()