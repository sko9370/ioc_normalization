import argparse
import os, sys
import csv
import re

# alienvault doesn't come with dates so you must manually organize them into folder directories with the date in
# mm-dd-yyyy format, regex will pick it up and add that as the dates for consistency with the other sources

# parses command line for path argument
parser = argparse.ArgumentParser()
parser.add_argument('-p', '--path', type=str, help='Specify target path of AlienVault IOC CSVs')
parser.add_argument('-o', '--out_path', type=str, help='Specify output file location')
args, commands = parser.parse_known_args()

if not args.path:
    print('Must provide path using -p')
    sys.exit(1)

# creating list of absolute file paths by joining args.path and filenames in its directory
# for Alienvault, need to extract date from directory, recurse one extra level
file_paths = []
dirs = os.listdir(args.path)
for dir in dirs:
    for file in os.listdir(os.path.join(args.path, dir)):
        file_paths.append(os.path.join(args.path, dir, file))

# parse relevant indicator types
dns = []
ip = []
url = []
md5 = []

# automatic parsing picks up something weird for first column name so manually specifying field names
fields = ['Indicator Type', 'Indicator', 'Description']

# iterate all files in path
for file_path in file_paths:
    with open(file_path) as in_file:
        # respects commas within fields by default
        rows = csv.DictReader(in_file, fieldnames=fields)
        for row in rows:
            row_with_date = row
            date = re.findall(r'[\d]{1,2}-[\d]{1,2}-[\d]{4}', file_path)
            row_with_date['Published'] = date[0]
            row_with_date['Updated'] = date[0]
            # second column is "Indicator Type"
            if row['Indicator Type'] == 'domain' or row['Indicator Type'] == 'hostname':
                dns.append(row_with_date)
            elif row['Indicator Type'] == 'IPv4':
                ip.append(row_with_date)
            elif row['Indicator Type'] == 'URL':
                url.append(row_with_date)
            elif row['Indicator Type'] == 'FileHash-MD5':
                md5.append(row_with_date)
            else:
                continue

# everything will be a list of dicts except loki_rows, it will be list of strings
dns_rows = []
ip_rows = []
url_rows = []
md5_rows = []
loki_rows = []

for input, output in [(dns, dns_rows), (ip, ip_rows), (url, url_rows), (md5, md5_rows)]:
    for row in input:
        # format into consistent format to match other sources
        clean_row = {
            'Indicator': row['Indicator'],
            'Published': row['Published'],
            'Updated': row['Updated'],
            'Context': row['Description']
        }
        output.append(clean_row)

# use command line argument as out path or use script location
if args.out_path:
    out_path = args.out_path
else:
    out_path = args.path

output_names = [
    (dns_rows, 'alienvault_dns.csv'),
    (ip_rows, 'alienvault_ip.csv'),
    (url_rows, 'alienvault_url.csv'),
    (md5_rows, 'alienvault_md5.csv')
]
out_fields = ['Indicator', 'Published', 'Updated', 'Context']
for out, filename in output_names:
    out_filepath = os.path.join(out_path, filename)
    # adds newline by default, set to none
    with open(out_filepath, 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=out_fields)

        writer.writeheader()
        for row in out:
            writer.writerow(row)

# write out loki format
with open(os.path.join(out_path, 'alienvault_md5.csv'), 'r') as in_file:
    with open(os.path.join(out_path, 'alienvault_loki_pre.txt'), 'w') as file:
        rows = csv.DictReader(in_file, fieldnames=out_fields)
        for row in rows:
            if row['Context']:
                file.write(row['Indicator'] + ';' + row['Context'] + ', ' + 'Downloaded: ' + row['Published'] + '\n')
            else:
                file.write(row['Indicator'] + ';' + 'Downloaded: ' + row['Published'] + '\n')

# can't figure out why some extra lines starting with the previous line's description, had to manually filter them out
with open(os.path.join(out_path, 'alienvault_loki_pre.txt'), 'r') as in_file:
    rows = in_file.readlines()[1:]
    with open(os.path.join(out_path, 'alienvault_loki.txt'), 'w') as file:
        for row in rows:
            if row.find('MD5', 0, 4) == -1:
                file.write(row)

os.remove(os.path.join(out_path, 'alienvault_loki_pre.txt'))

if __name__ == '__main__':
    pass