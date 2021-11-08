import argparse
import os, sys
#import pandas as pd
import csv

# parses command line for path argument
parser = argparse.ArgumentParser()
parser.add_argument('-p', '--path', type=str, help='Specify target path of CrowdStrike IOC CSVs')
parser.add_argument('-o', '--out_path', type=str, help='Specify output file location')
args, commands = parser.parse_known_args()

if not args.path:
    print('Must provide path using -p')
    sys.exit(1)

# creating list of absolute file paths by joining args.path and filenamess in its directory
file_paths = [os.path.join(args.path, file) for file in os.listdir(args.path)]

# parse relevant indicator types
dns = []
ip = []
url = []
md5 = []

# automatic parsing picks up something weird for first column name so manually specifying field names
fields = ['indicator', 'type', 'malware_families', 'actors', 'reports', 'kill_chains', 'published_date', 'last_updated', 'malicious_confidence', 'labels']

# iterate all files in path
for file_path in file_paths:
    with open(file_path) as in_file:
        # respects commas within fields by default
        rows = csv.DictReader(in_file, fieldnames=fields)
        for row in rows:
            # second column is "Indicator Type"
            if row['type'] == 'domain':
                dns.append(row)
            elif row['type'] == 'ip_address':
                ip.append(row)
            elif row['type'] == 'url':
                url.append(row)
            elif row['type'] == 'hash_md5':
                md5.append(row)

# everything will be a list of dicts except loki_rows, it will be list of strings
dns_rows = []
ip_rows = []
url_rows = []
md5_rows = []
loki_rows = []

for input, output in [(dns, dns_rows), (ip, ip_rows), (url, url_rows), (md5, md5_rows)]:
    for row in input:
        context = [
            row['malware_families'],
            row['actors'],
            row['labels'],
            'Published: ' + row['published_date'],
            'Updated: ' + row['last_updated']
        ]
        # special formatting for loki
        if input == md5:
            loki_rows.append(row['indicator'] + ';' + ', '.join(filter(None, context)))
        # format into consistent format to match other sources
        clean_row = {
            'Indicator': row['indicator'],
            'Published': row['published_date'],
            'Updated': row['last_updated'],
            'Context': ', '.join([row['malware_families'], row['actors'], row['labels']])
        }
        output.append(clean_row)

# use command line argument as out path or use script location
if args.out_path:
    out_path = args.out_path
else:
    out_path = args.path

# write out loki format
with open(os.path.join(out_path, 'crowdstrike_loki.txt'), 'w') as file:
    file.write('\n'.join(loki_rows))

output_names = [
    (dns_rows, 'crowdstrike_dns.csv'),
    (ip_rows, 'crowdstrike_ip.csv'),
    (url_rows, 'crowdstrike_url.csv'),
    (md5_rows, 'crowdstrike_md5.csv')
]
for out, filename in output_names:
    out_filepath = os.path.join(out_path, filename)
    # adds newline by default, set to none
    with open(out_filepath, 'w', newline='') as file:
        out_fields = ['Indicator', 'Published', 'Updated', 'Context']
        writer = csv.DictWriter(file, fieldnames=out_fields)

        writer.writeheader()
        for row in out:
            writer.writerow(row)

if __name__ == '__main__':
    pass