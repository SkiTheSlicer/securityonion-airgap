#!/usr/bin/python
# Created by https://github.com/SkiTheSlicer
# Ref: /var/www/so/squert/.scripts/ip2c.tcl
# Ref: /var/www/so/squert/.scripts/squert.sql
# Req: http://repo.mysql.com/apt/ubuntu/pool/connector-python-2.1/m/mysql-connector-python/

def parse_arguments():
  import argparse
  import os
  import sys
  parser = argparse.ArgumentParser(
    prog='squert_ip2c_update.py',
    description='Update SQueRT\'s ip2c table in Security Onion.',
    epilog='Created by SkiTheSlicer (https://github.com/SkiTheSlicer)')
    #formatter_class=argparse.RawTextHelpFormatter)
  parser.add_argument('-d', '--source-dir',
                      nargs='?',
                      help='Specifies directory containing RIR updates.')
  return parser.parse_args()

def read_table(db_name, table_name):
  import mysql.connector
  import os
  print "Reading table " + table_name
 #Connect to database
  config = {
    'user': 'root',
    'password': '',
    'host': '127.0.0.1',
    'database': db_name
  }
  cnx = mysql.connector.connect(**config)
  #cursor = cnx.cursor()
 ##Show table
 # select_stmt = "SELECT * FROM " + table_name
 # cursor.execute(select_stmt) #Count
 # rows = cursor.fetchall()
 # for row in rows:
 #   print row
 #Results
  cursor = cnx.cursor(buffered=True)
  cursor.execute('SELECT COUNT(*) FROM ' + table_name)
  rows_total = cursor.fetchone()[0]
  print "  Total Table Rows:  " + str(rows_total)
  cursor.execute('SELECT COUNT(DISTINCT start_ip) FROM ' + table_name)
  rows_unique = cursor.fetchone()[0]
  print "  Unique Table Rows: " + str(rows_unique)
 #Close connection to database
  cursor.close()
  cnx.close()

def create_table(db_name, table_name):
  print "(Re)Creating table " + table_name
  import mysql.connector
 #Connect to database
  config = {
    'user': 'root',
    'password': '',
    'host': '127.0.0.1',
    'database': db_name
  }
  cnx = mysql.connector.connect(**config)
  cursor = cnx.cursor()
 #Remove table if already exists
  try:
    cursor.execute("DROP TABLE IF EXISTS " + table_name)
    print "  Dropped table " + table_name
  except:
    print "  No table " + table_name + " to DROP"
 #Create table statement
  create_stmt = (
    "CREATE TABLE " + table_name + " ("
    "  `registry` VARCHAR(7),"
    "  `cc` VARCHAR(2),"
    "  `c_long` VARCHAR(255),"
    "  `type` VARCHAR(4),"
    "  `start_ip` INT(10) UNSIGNED NOT NULL DEFAULT 0,"
    "  `end_ip` INT(10) UNSIGNED NOT NULL DEFAULT 0,"
    "  `date` DATETIME,"
    "  `status` VARCHAR(25),"
    "   INDEX `registry` (`registry`),"
    "   INDEX `cc` (`cc`),"
    "   INDEX `c_long` (`c_long`),"
    "   INDEX `type` (`type`),"
    "   INDEX `start_ip` (`start_ip`),"
    "   INDEX `end_ip` (`end_ip`)"
    ") ENGINE=InnoDB")
  insert_stmt = ("INSERT IGNORE INTO " + table_name + " "
                "(registry, cc, c_long, type, start_ip, end_ip, date, status) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)")
  insert_data = [
    ("RFC1918", "LO", "RFC1918", "ipv4",  167772160,  184549375, 19960201, "allocated"),
    ("RFC1918", "LO", "RFC1918", "ipv4", 2886729728, 2886795263, 19960201, "allocated"),
    ("RFC1918", "LO", "RFC1918", "ipv4", 3232235520, 3232301055, 19960201, "allocated")
  ]
  cursor.execute(create_stmt)
  for entry in insert_data:
    cursor.execute(insert_stmt, entry)
  cnx.commit()
 #Close connection
  cursor.close()
  cnx.close()
  print "  (Re)Creation complete"
  
def update_table(db_name, table_name, input_file):
  import os
  import sys
  import mysql.connector
  print "Updating table " + table_name + " from " + input_file
 #Ensure results file exists
  if not os.path.exists(input_file):
    print "No temp file"
    sys.exit(1)
 #Connect to database
  config = {
    'user': 'root',
    'password': '',
    'host': '127.0.0.1',
    'database': db_name
  }
  cnx = mysql.connector.connect(**config)
  cursor = cnx.cursor()
 #Delete entries if doing an update, not initial population
  try:
    cursor.execute('SELECT COUNT(*) FROM ' + table_name)
    rows_total = cursor.fetchone()[0]
    if rows_total > 3:
      print "  Already Updated. Updating Again..."
      cursor.close()
      cnx.close()
      create_table(db_name, table_name)
      cnx = mysql.connector.connect(**config)
      cursor = cnx.cursor()
    else:
      print "  Performing Initial Update..."
  except:
    print "  Table " + table_name + " doesn't exist"
    create_table(db_name, table_name)
 #Load table from file
  cursor.execute("LOAD DATA LOCAL INFILE '" + input_file + "' INTO TABLE " + table_name + " FIELDS TERMINATED BY '|' ")
  cnx.commit()
 #Close connection to database
  cursor.close()
  cnx.close()
  os.remove(input_file)
  print "Update complete"

def create_tmp_file(source_dir, temp_file):
  import os
  import csv
  #import re
  print "Creating temp file " + temp_file + " from dir " + source_dir
  if os.path.exists("/var/www/so/squert/.inc/countries.php"):
    country_php = "/var/www/so/squert/.inc/countries.php"
  elif os.path.exists("/var/www/squert/.inc/countries.php"):
    country_php = "/var/www/squert/.inc/countries.php"
  else:
    country_php = os.path.join('.', 'countries.php')
  try:
    os.remove(temp_file)
    print "  Temp file already exists. Deleting."
  except OSError:
    pass
  items = os.listdir(source_dir)
  with open(temp_file, 'wb') as output_file:
    csvwriter = csv.writer(output_file, delimiter='|')
    for item in items:
      if item.endswith("-extended-latest"):
      #re.compile("delegated-[a-z]+-extended-latest")
        print "Parsing " + item + " to " + os.path.basename(temp_file) + "..."
        entry_skipped = 0
        entry_added = 0
        with open(os.path.join(source_dir, item), 'rb') as input_file:
          csvreader = csv.reader(input_file, delimiter='|')
          for row in csvreader:
            if not row[0].startswith('#') and row[2] == 'ipv4' and row[3] != '*':
              entry_added = entry_added + 1
             #Convert subnet into range
              start = row[3]
              value = row[4]
              result = convert_ip_range(start, value)
             #Convert cc to c_long
              cc = row[1]
              c_long = convert_country_code(cc, country_php)
             #Continue
              registry = row[0]
              type = row[2]
              start_ip = result[0]
              end_ip = result[1]
              date = row[5]
              status = row[6]
             #Update tmp file
              csvwriter.writerow([registry, cc, c_long, type, start_ip, end_ip, date, status])
             ##Create Lists
             # insert_stmt = ("INSERT INTO " + table_name + " "
             #                 "(registry, cc, c_long, type, start_ip, end_ip, date, status) "
             #                 "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)")
             # insert_data = (registry, cc, c_long, type, start_ip, end_ip, date, status)
             ##Update
             # try:
             #     cursor.execute(insert_stmt, insert_data)
             #     cnx.commit()
             # except:
             #     cnx.rollback()
            else:
              entry_skipped = entry_skipped + 1
        print "  Added " + str(entry_added) + " entries from " + item
        print "  Skipped " + str(entry_skipped) + " entries in " + item

def convert_ip_range(starting_ip, total_ips):
 #Split
  ip_parts = starting_ip.split('.')
  o1 = int(ip_parts[0])
  o2 = int(ip_parts[1])
  o3 = int(ip_parts[2])
  o4 = int(ip_parts[3])
 #Math
  n1 = o1*16777216
  n2 = o2*65536
  n3 = o3*256
 #New Variables
  ip_start = n1+n2+n3+o4
  ip_end = ip_start+(int(total_ips)-1)
 #Output
  answer = [ip_start, ip_end]
  return answer

def convert_country_code(country_code, countries_file):
  search_string = "|" + country_code + "|"
  country_name = 'Unknown'
  for line in open(countries_file, 'r'):
    if search_string in line:
      country_name = line.split('|')[0][1:]
      break
  return country_name

def main():
  try:
    import mysql.connector
  except:
    import sys
    print "\n[IP2C: WARNING]"
    print 'ERROR: mysql.connector library not available. Exitting...'
    sys.exit(1)
  import os
  args = parse_arguments()
  try:
    csv_file = os.path.join(os.environ['tmp'], 'ip2c-results.csv')
  except:
    csv_file = os.path.join('/tmp', 'ip2c-results.csv')
  ##create_table("securityonion_db", "ip2c")
  print "\n[IP2C: Parse RIR DBs]"
  create_tmp_file(args.source_dir, csv_file)
  print "\n[IP2C: Update MySQL DB]"
  update_table("securityonion_db", "ip2c", csv_file)
  print "\n[IP2C: Update Validation]"
  read_table("securityonion_db", "ip2c")

if __name__ == "__main__":
  main()
