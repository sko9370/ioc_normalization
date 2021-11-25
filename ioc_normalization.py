import argparse
import os, sys
import csv
import pandas as pd
from datetime import datetime
from datetime import date
from urllib.parse import urlparse

import utils
import alienvault
import crowdstrike
import mandiant

# parses command line for path argument
parser = argparse.ArgumentParser()
parser.add_argument('-p', '--path', type=str, help='Specify target path of IOC CSVs')
parser.add_argument('-o', '--out_path', type=str, help='Specify output file path')
parser.add_argument('-w', '--wildcard', action='store_true', help='Turn on wildcard column for dns for more flexible matching')
args, commands = parser.parse_known_args()

if not args.path:
    print('Must provide input CSVs\' path using -p')
    sys.exit(1)

# get file paths for all csvs in target path by searching recursively for *.csv
file_paths = utils.get_file_paths(args.path)

# take in different sources based on header (line 1 of csv)
# then organize based on indicator type
dns_dfs = []
ip_dfs = []
url_dfs = []
md5_dfs = []
sha1_dfs = []
sha256_dfs = []
email_dfs = []
ja3_dfs = []

# preprocessing of input csvs
for file_path in file_paths:
    with open(file_path) as in_file:
        try:
            header = in_file.readline().rstrip()
            # reset file pointer so .read_csv can see headers
            in_file.seek(0)
        except:
            header = ''
        full_filename = os.path.basename(file_path)
        # check for AlienVault header
        if alienvault.header() in header:
            temp_df = alienvault.preprocess(in_file, full_filename)
            # distribute IOCs to respective dataframes by type
            dns_dfs.append(alienvault.get_domains(temp_df))
            dns_dfs.append(alienvault.get_hostnames(temp_df))
            ip_dfs.append(alienvault.get_ips(temp_df))
            url_dfs.append(alienvault.get_urls(temp_df))
            md5_dfs.append(alienvault.get_md5s(temp_df))
            #ja3_dfs.append(temp_df[temp_df['Type'] == 'JA3'])
        # check for CrowdStrike header
        elif crowdstrike.header() in header:
            temp_df = crowdstrike.preprocess(in_file)
            dns_dfs.append(crowdstrike.get_domains(temp_df))
            ip_dfs.append(crowdstrike.get_ips(temp_df))
            url_dfs.append(crowdstrike.get_urls(temp_df))
            md5_dfs.append(crowdstrike.get_md5s(temp_df))
            # ja3??
        # check for FireEye header
        # files have an odd character in line so can't do an exact match
        elif mandiant.header() in header:
            temp_df = mandiant.preprocess(in_file)
            dns_dfs.append(mandiant.get_domains(temp_df))
            ip_dfs.append(mandiant.get_ips(temp_df))
            url_dfs.append(mandiant.get_urls(temp_df))
            md5_dfs.append(mandiant.get_md5s(temp_df))
            sha1_dfs.append(mandiant.get_sha1s(temp_df))
            sha256_dfs.append(mandiant.get_sha256s(temp_df))
            # ja3??
        elif ".xlsx" in full_filename:
            temp_df = pd.read_excel(file_path)
            # type 2
            if 'uuid' in temp_df.columns:
                # create Published and Updated columns from modified date
                temp_df['Published'] = temp_df['date'].apply(lambda x: date.fromtimestamp(x).isoformat())
                temp_df['Updated'] = temp_df['date'].apply(lambda x: date.fromtimestamp(x).isoformat())
                # need to replace NaN's (NONE in pandas) with empty strings to concatenate
                temp_df.fillna('', inplace=True)
                # create Attribution column from the filename, event_id, comment, and attribute_tag
                filename, ext = os.path.splitext(full_filename)
                temp_df.loc[temp_df['comment'] != '', 'Attribution'] = filename + ': ' + 'Comment=' + temp_df['comment'] + '; event_id=' + temp_df['event_id'].astype(str) + '; attribute_tag=' + temp_df['attribute_tag']
                temp_df.loc[temp_df['comment'] == '', 'Attribution'] = filename + ': ' + 'event_id=' + temp_df['event_id'].astype(str) + '; attribute_tag=' + temp_df['attribute_tag']
                # create Source column
                temp_df['Source'] = 'TF'
                # drop unnecessary columns
                unnecessary_columns = ['uuid', 'event_id', 'comment', 'attribute_tag', 'category', 'to_ids', 'object_relation', 'object_uuid', 'object_name', 'object_meta_category', 'date']
                temp_df.drop(unnecessary_columns, axis=1, inplace=True)
                # normalize column names
                temp_df.rename(columns = {'type':'Type', 'value':'Indicator'}, inplace=True)
                # rename columns
                temp_df.columns = ['Type', 'Indicator', 'Published', 'Updated', 'Attribution', 'Source']
                # reorder column names
                temp_df = temp_df[['Indicator', 'Type', 'Published', 'Updated', 'Attribution', 'Source']]
                dns_dfs.append(temp_df[temp_df['Type'] == 'domain'])
                # strip port number from ip address 
                temp_df['Indicator'] = temp_df['Indicator'].apply(lambda x: x if '|' not in x else x.split('|')[0])
                ip_dfs.append(temp_df[temp_df['Type'] == 'ip-dst|port'])
                ip_dfs.append(temp_df[temp_df['Type'] == 'ip-dst'])
                url_dfs.append(temp_df[temp_df['Type'] == 'url'])
                md5_dfs.append(temp_df[temp_df['Type'] == 'md5'])
                sha256_dfs.append(temp_df[temp_df['Type'] == 'sha256'])
                email_dfs.append(temp_df[temp_df['Type'] == 'email-src'])
            # type 1
            else:
                # need to replace NaN's (NONE in pandas) with empty strings to concatenate
                temp_df.fillna('', inplace=True)
                # create Context column from the filename, event_id, comment, and attribute_tag
                filename, ext = os.path.splitext(full_filename)
                temp_df['Attribution'] = filename
                temp_df['Source'] = 'TF'
                # use last modified time as Published and Updated values
                time = date.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                temp_df['Published'] = time
                temp_df['Updated'] = time
                # dummy column for consistency
                temp_df['Type'] = ''
                if 'Domains' in temp_df.columns:
                    step_df = temp_df[['Domains', 'Type', 'Published', 'Updated', 'Attribution', 'Source']]
                    step_df.rename(columns = {'Domains':'Indicator'}, inplace=True)
                    dns_dfs.append(step_df)
                if 'IP Addresses' in temp_df.columns:
                    step_df = temp_df[['IP Addresses', 'Type', 'Published', 'Updated', 'Attribution', 'Source']]
                    step_df.rename(columns = {'IP Addresses':'Indicator'}, inplace=True)
                    ip_dfs.append(step_df)
                if 'URLs' in temp_df.columns:
                    step_df = temp_df[['URLs', 'Type', 'Published', 'Updated', 'Attribution', 'Source']]
                    step_df.rename(columns = {'URLs':'Indicator'}, inplace=True)
                    url_dfs.append(step_df)
                if 'Hashes' in temp_df.columns:
                    temp_df['md5'] = temp_df['Hashes'].apply(lambda x: x if len(x) == 32 else '')
                    temp_df['sha1'] = temp_df['Hashes'].apply(lambda x: x if len(x) == 40 else '')
                    temp_df['sha256'] = temp_df['Hashes'].apply(lambda x: x if len(x) == 64 else '')

                    step_df = temp_df[['md5', 'Type', 'Published', 'Updated', 'Attribution', 'Source']]
                    step_df = step_df[step_df['md5'].astype(bool)].copy()
                    step_df.rename(columns = {'md5':'Indicator'}, inplace=True)
                    #print(step_df)
                    md5_dfs.append(step_df)

                    step_df = temp_df[['sha1', 'Type', 'Published', 'Updated', 'Attribution', 'Source']]
                    step_df = step_df[step_df['sha1'].astype(bool)].copy()
                    step_df.rename(columns = {'sha1':'Indicator'}, inplace=True)
                    #print(step_df)
                    sha1_dfs.append(step_df)

                    step_df = temp_df[['sha256', 'Type', 'Published', 'Updated', 'Attribution', 'Source']]
                    step_df = step_df[step_df['sha256'].astype(bool)].copy()
                    step_df.rename(columns = {'sha256':'Indicator'}, inplace=True)
                    #print(step_df)
                    sha256_dfs.append(step_df)
                if 'Email Addresses' in temp_df.columns:
                    step_df = temp_df[['Email Addresses', 'Type', 'Published', 'Updated', 'Attribution', 'Source']]
                    step_df.rename(columns = {'Email Addresses':'Indicator'}, inplace=True)
                    email_dfs.append(step_df)

# use command line argument as out path or use script location
if args.out_path:
    out_path = args.out_path
else:
    out_path = args.path

# validate IP address function
def validate_ip(address):
    try:
        for octet in str(address).split('.'):
            if int(octet) < 0 or int(octet) > 255:
                return False 
        return True
    except:
        return False

# parse domain function
def get_domain(url):
    o = urlparse(url)
    return o.netloc.split(':')[0]

# have to check if list of dfs is empty because .concat will throw error
# deduplicate
# write out to csv
# check for args.wildcard commandline argument and add wildcard column if enabled
if url_dfs:
    url_df = pd.concat(url_dfs)
    # parse out IPs and add to ip_dfs
    url_df['IP'] = url_df['Indicator'].str.extract(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    url_df.fillna('', inplace=True)
    url_df['IP'] = url_df['IP'].apply(lambda x: x if validate_ip(x) else '')
    temp_df = url_df[['IP', 'Type', 'Published', 'Updated', 'Attribution', 'Source']] 
    temp_df = temp_df[temp_df['IP'].astype(bool)].copy()
    temp_df.rename(columns = {'IP':'Indicator'}, inplace=True)
    temp_df = temp_df[['Indicator', 'Type', 'Published', 'Updated', 'Attribution', 'Source']]
    ip_dfs.append(temp_df)
    # parse out domain and add to dns_dfs
    # some domains are false positives, hold off on this
    url_df['Domain'] = url_df['Indicator'].apply(lambda x: get_domain(x))
    # parse out path
    url_df['Path'] = url_df['Indicator'].str.extract(r'[\.:][a-zA-Z0-9]+(/.+$)')
    url_df['Path'] = url_df['Path'].apply(lambda x: x if x != '\\' else '')
    #url_df.drop(['Type', 'IP'], axis=1, inplace=True)
    url_df.drop(['Type'], axis=1, inplace=True)
    url_df = url_df[['Indicator', 'Domain', 'IP', 'Path', 'Published', 'Updated', 'Attribution', 'Source']]
    url_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    url_df.to_csv(os.path.join(out_path, 'url_all.csv'), index = False)
if dns_dfs:
    dns_df = pd.concat(dns_dfs)
    dns_df.drop(['Type'], axis=1, inplace=True)
    #print(dns_df)
    dns_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    if args.wildcard:
        dns_df['Wildcard'] = dns_df['Indicator'].apply(lambda x: '*' + x + '*') 
        dns_df = dns_df[['Indicator', 'Wildcard', 'Published', 'Updated', 'Context']]
    dns_df.to_csv(os.path.join(out_path, 'dns_all.csv'), index = False)
if ip_dfs:
    ip_df = pd.concat(ip_dfs)
    ip_df.drop(['Type'], axis=1, inplace=True)
    #print(ip_df)
    ip_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    ip_df.to_csv(os.path.join(out_path, 'ip_all.csv'), index = False)
if md5_dfs:
    md5_df = pd.concat(md5_dfs)
    md5_df.drop(['Type'], axis=1, inplace=True)
    #print(md5_df)
    md5_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    md5_df.to_csv(os.path.join(out_path, 'md5_all.csv'), index = False)

    # write loki format
    with open(os.path.join(out_path, 'md5_all.csv'), 'r') as in_file:
        with open(os.path.join(out_path, 'pre_loki.txt'), 'w') as file:
            rows = csv.DictReader(in_file, fieldnames=['Indicator', 'Published', 'Updated', 'Attribution', 'Source'])
            for row in rows:
                comment = ', '.join(filter(None, ['Attribution: ' + row['Attribution'], 'Source: ' + row['Source']]))
                file.write(row['Indicator'] + '; ' + comment + 'Downloaded: ' + row['Published'] + '\n')
    
    # can't figure out why some extra lines starting with the previous line's description, had to manually filter them out
    with open(os.path.join(out_path, 'pre_loki.txt'), 'r') as in_file:
        rows = in_file.readlines()[1:]
        with open(os.path.join(out_path, 'hash_loki.txt'), 'w') as file:
            for row in rows:
                if row.find('MD5', 0, 4) == -1:
                    file.write(row)

    os.remove(os.path.join(out_path, 'pre_loki.txt'))

if sha1_dfs:
    sha1_df = pd.concat(sha1_dfs)
    sha1_df.drop(['Type'], axis=1, inplace=True)
    #print(sha1_df)
    sha1_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    sha1_df.to_csv(os.path.join(out_path, 'sha1_all.csv'), index = False)
if sha256_dfs:
    sha256_df = pd.concat(sha256_dfs)
    sha256_df.drop(['Type'], axis=1, inplace=True)
    #print(sha256_df)
    sha256_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    sha256_df.to_csv(os.path.join(out_path, 'sha256_all.csv'), index = False)
if email_dfs:
    email_df = pd.concat(email_dfs)
    email_df.drop(['Type'], axis=1, inplace=True)
    #print(email_df)
    email_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    email_df.to_csv(os.path.join(out_path, 'email_all.csv'), index = False)
if len(ja3_dfs) > 0:
    ja3_df = pd.concat(ja3_dfs)
    ja3_df.drop(['Type'], axis=1, inplace=True)
    #print(ja3_df)
    ja3_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    ja3_df.to_csv(os.path.join(out_path, 'ja3_all.csv'), index = False)