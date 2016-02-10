#!/usr/bin/python
# Created by https://github.com/SkiTheSlicer

#from securityonion_airgap_download import compare_md5s

def parse_arguments():
  import argparse
  import os
  import sys
  parser = argparse.ArgumentParser(
    prog='securityonion_airgap_update.py',
    description='Update tools within Security Onion.',
    epilog='Created by SkiTheSlicer (https://github.com/SkiTheSlicer)')
  parser.add_argument('-f', '--input-file',
                      nargs='?',
                      help='Specifies compressed archive containing updates')
  parser.add_argument('-g', '--geoip',
                      action='store_true',
                      help='Perform Bro GeoIP updates only.')
  parser.add_argument('-r', '--rules',
                      action='store_true',
                      help='Perform Snort rule updates only.')
  parser.add_argument('-i', '--ip2c',
                      action='store_true',
                      help='Perform SQueRT ip2c updates only.')
  return parser.parse_args()

def decompress_tarfile(file_to_decompress):
  import os
  import tarfile
  import sys
  if not os.path.isdir(file_to_decompress) and file_to_decompress.endswith('.tar.gz'):
    print "Decompressing " + file_to_decompress + "..."
    with tarfile.open(file_to_decompress) as tar:
      tar.extractall()
  else:
    print "Invalid tar file."
    sys.exit(1)

def main():
  import os
  import sys
  from securityonion_airgap_download import compare_md5s
  import subprocess
  args = parse_arguments()
  if not os.path.exists(args.input_file):
    print args.input_file + ' doesn\'t exist. Exitting.'
    sys.exit(1)
  elif os.path.isdir(args.input_file):
    #for f in os.listdir(args.input_file):
    #  file = os.join(args.input_file, f)
    print 'Script currently doesn\'t support crawling a directory. Exitting.'
      #Maybe list dir, select newest tarball, and overwrite value of args.input_file. Then change next elseif to just if.
    sys.exit(1)
  elif not os.path.isdir(args.input_file):
    if os.path.exists('.'.join([args.input_file, 'md5'])):
      compare_md5s(os.path.dirname(os.path.abspath(args.input_file)))
    decompress_tarfile(args.input_file)
    base_dir = args.input_file[:-7]
    script_dir = os.path.dirname(os.path.realpath(__file__))
    ip2c_script = script_dir + '/squert_ip2c_update.py'
    #ip2c_cmd = script_dir + '/squert_ip2c_update.py -d ' + os.path.join(base_dir, 'RIR')
    ids_script = script_dir + '/ids_offline_update.py'
    #print os.path.abspath(base_dir)
    if args.geoip:
      print 'Do geoip'
      subprocess.call(['python', ids_script, '--geoip', '-G' + os.path.join(os.path.abspath(base_dir), 'GeoIP')])
    elif args.rules:
      print 'Do rules'
      # what about Doing blacklist?
      subprocess.call(['python', ids_script, '--rules', '-R' + os.path.join(os.path.abspath(base_dir), 'Snort')])
    elif args.ip2c:
      print 'Do ip2c'
      ##subprocess.call(['python', ip2c_script, '-h'])
      ##subprocess.call(['python', ip2c_cmd])
      subprocess.call(['python', ip2c_script, '-d' + os.path.join(os.path.abspath(base_dir), 'RIR')])
      ##subprocess.call(['sudo', 'python', ip2c_script, '-d' + os.path.join(os.path.abspath(base_dir), 'RIR')])
    else:
      print 'Do geoip & Do rules'
      subprocess.call(['python', ids_script, '-B' + os.path.join(os.path.abspath(base_dir), 'Snort', 'Blacklist'), '-G' + os.path.join(os.path.abspath(base_dir), 'GeoIP'), '-R' + os.path.join(os.path.abspath(base_dir), 'Snort')])
      print 'Do ip2c'
      subprocess.call(['python', ip2c_script, '-d' + os.path.join(os.path.abspath(base_dir), 'RIR')])

if __name__ == "__main__":
  main()