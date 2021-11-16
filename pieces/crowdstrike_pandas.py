import argparse
import os, sys
import csv
import pandas as pd

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

dfs = []

for file in file_paths:
    dfs.append(pd.read_csv(file, index_col=0, dtype='unicode'))

df = pd.concat(dfs)
df.drop(['reports', 'kill_chains', 'malicious_confidence'], axis=1, inplace=True)
df.rename(columns = {'published_date':'Published', 'last_updated':'Updated', 'labels': 'Context'}, inplace=True)
df.columns.names = ['Indicator']
df.index.name = 'Indicator' 
# label columns contains all other context information
#df['Context'] = df['malware_families'] + ' ' + df['actors'] + ' ' + df['labels']
df.drop(['malware_families', 'actors'], axis=1, inplace=True)

dns_df = df[df['type'] == 'domain']
ip_df = df[df['type'] == 'ip_address']
url_df = df[df['type'] == 'url']
md5_df = df[df['type'] == 'hash_md5']


df_list = [(dns_df, 'crowdstrike_dns.csv'), (ip_df, 'crowdstrike_ip.csv'), (url_df, 'crowdstrike_url.csv'), (md5_df, 'crowdstrike_md5.csv')]

# use command line argument as out path or use script location
if args.out_path:
    out_path = args.out_path
else:
    out_path = args.path

for df, filename in df_list:
    df.drop('type', axis=1, inplace=True)
    df.to_csv(os.path.join(out_path, filename))

out_fields = ['Indicator', 'Published', 'Updated', 'Context']
# write out loki format
with open(os.path.join(out_path, 'crowdstrike_md5.csv'), 'r') as in_file:
    with open(os.path.join(out_path, 'crowdstrike_loki_pre.txt'), 'w') as file:
        rows = csv.DictReader(in_file, fieldnames=out_fields)
        for row in rows:
            file.write(row['Indicator'] + ';' + row['Context'] + ', ' + 'Published: ' + row['Published'] + 'Updated: ' + row['Updated'] + '\n')

# can't figure out why some extra lines starting with the previous line's description, had to manually filter them out
with open(os.path.join(out_path, 'crowdstrike_loki_pre.txt'), 'r') as in_file:
    rows = in_file.readlines()[1:]
    with open(os.path.join(out_path, 'crowdstrike_loki.txt'), 'w') as file:
        for row in rows:
            if row.find('MD5', 0, 4) == -1:
                file.write(row)

os.remove(os.path.join(out_path, 'crowdstrike_loki_pre.txt'))