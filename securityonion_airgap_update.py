#!/usr/bin/python
# 20160109  https://github.com/SkiTheSlicer

#from securityonion_airgap_download import calculate_md5
from securityonion_airgap_download import compare_md5s

def parse_arguments():
  #from datetime import datetime
  import argparse
  import os
  import sys
  #datetime_now = datetime.now().strftime('%Y%m%d-%H%M')
  parser = argparse.ArgumentParser(
    prog='securityonion_airgap_update.py',
    description='Update tools within Security Onion.',
    epilog='Created by SkiTheSlicer (https://github.com/SkiTheSlicer)')
    #formatter_class=argparse.RawTextHelpFormatter)
  parser.add_argument('-g', '--geoip',
                      action='store_true'
                      help='Perform Bro GeoIP updates only.')
  parser.add_argument('-r', '--rules',
                      action='store_true'
                      help='Perform Snort rule updates only.')
  parser.add_argument('-i', '--ip2c',
                      action='store_true'
                      help='Perform SQueRT ip2c updates only.')
  parser.add_argument('-f', '--input-file',
                      nargs='?', default=".",
                      help='Specifies compressed archive containing updates')      
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

def main()
  import os
  args = parse_arguments
  if not os.path.exists(args.input_file):
    print args.input_file + ' doesn't exist. Exitting.'
    sys.exit(1)
  elif os.path.isdir(args.input_file):
    for f in os.listdir(args.input_file):
      file = os.join(args.input_file, f)
  elif not os.path.isdir(args.input_file):
    decompress_tarfile(args.input_file)
    

if __name__ == "__main__":
  main()