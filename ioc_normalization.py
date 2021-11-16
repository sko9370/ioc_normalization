import argparse
import os, sys
import csv
import re
import pandas as pd
from datetime import datetime
from datetime import date

# parses command line for path argument
parser = argparse.ArgumentParser()
parser.add_argument('-p', '--path', type=str, help='Specify target path of IOC CSVs')
parser.add_argument('-o', '--out_path', type=str, help='Specify output file path')
args, commands = parser.parse_known_args()

if not args.path:
    print('Must provide input CSVs\' path using -p')
    sys.exit(1)

# get file paths for all csvs in target path by searching recursively for *.csv
topdir = args.path
extensions = ['.csv', '.xlsx']
file_paths = []

for dirpath, dirnames, files in os.walk(topdir):
    for name in files:
        if name.lower().endswith(extensions[0]):
            file_paths.append(os.path.join(dirpath, name))
        elif name.lower().endswith(extensions[1]):
            file_paths.append(os.path.join(dirpath, name))

# take in different sources based on header (line 1 of csv)
# then organize based on indicator type
dns_dfs = []
ip_dfs = []
url_dfs = []
md5_dfs = []
sha1_dfs = []
sha256_dfs = []
email_dfs = []

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
        if header == "\"Indicator type\",\"Indicator\",\"Description\"":
            temp_df = pd.read_csv(in_file, header=0, dtype='unicode')
            # parse filename for context and date since most alienvault entries
            # do not have that information
            filename, end = full_filename.split('_')
            date_field, extension = os.path.splitext(end)
            temp_df['Published'] = date_field
            temp_df['Updated'] = date_field
            # need to replace NaN's (NONE in pandas) with empty strings to concatenate
            temp_df.fillna('', inplace=True)
            # add filename as Context
            temp_df.loc[temp_df['Description'] == '', 'Context'] = filename
            temp_df.loc[temp_df['Description'] != '', 'Context'] = filename + ': ' + temp_df['Description']
            # drop Description column now because redundant with Context
            temp_df.drop(['Description'], axis=1, inplace=True)
            # normalize column names
            temp_df.rename(columns = {'Indicator type':'Type'}, inplace=True)
            # reorder column names
            temp_df = temp_df[['Indicator', 'Type', 'Published', 'Updated', 'Context']]
            # add dns IOCs
            dns_dfs.append(temp_df[temp_df['Type'] == 'domain'])
            dns_dfs.append(temp_df[temp_df['Type'] == 'hostname'])
            ip_dfs.append(temp_df[temp_df['Type'] == 'IPv4'])
            url_dfs.append(temp_df[temp_df['Type'] == 'URL'])
            md5_dfs.append(temp_df[temp_df['Type'] == 'FileHash-MD5'])
        # check for CrowdStrike header
        elif header == "indicator,type,malware_families,actors,reports,kill_chains,published_date,last_updated,malicious_confidence,labels":
            temp_df = pd.read_csv(in_file, header=0, dtype='unicode')
            # drop unnecessary columns
            unnecessary_columns = ['reports','kill_chains','malicious_confidence','malware_families','actors']
            temp_df.drop(unnecessary_columns, axis=1, inplace=True)
            # normalize column names
            temp_df.rename(columns = {'indicator':'Indicator', 'type':'Type', 'published_date':'Published', 'last_updated':'Updated', 'labels': 'Context'}, inplace=True)
            # format datetime into just date YYYY-MM-DD
            temp_df['Published'] = temp_df['Published'].apply(lambda x: x[:10])
            temp_df['Updated'] = temp_df['Updated'].apply(lambda x: x[:10])
            dns_dfs.append(temp_df[temp_df['Type'] == 'domain'])
            ip_dfs.append(temp_df[temp_df['Type'] == 'ip_address'])
            url_dfs.append(temp_df[temp_df['Type'] == 'url'])
            md5_dfs.append(temp_df[temp_df['Type'] == 'hash_md5'])
        # check for FireEye header
        # files have an odd character in line so can't do an exact match
        elif "\"Indicator Value\",\"Indicator Type\",\"Associations\",\"Exclusive\",\"First Seen\",\"Last Seen\"" in header:
            temp_df = pd.read_csv(in_file, header=0, dtype='unicode')
            temp_df.drop(['Exclusive'], axis=1, inplace=True)
            # rename columns
            temp_df.columns = ['Indicator', 'Type', 'Context', 'Published', 'Updated']
            # reorder columns
            temp_df = temp_df[['Indicator', 'Type', 'Published', 'Updated', 'Context']]
            temp_df['Published'] = temp_df['Published'].apply(lambda x: datetime.strptime(x, '%B %d, %Y').strftime('%Y-%m-%d'))
            temp_df['Updated'] = temp_df['Updated'].apply(lambda x: datetime.strptime(x, '%B %d, %Y').strftime('%Y-%m-%d'))
            dns_dfs.append(temp_df[temp_df['Type'] == 'FQDN'])
            ip_dfs.append(temp_df[temp_df['Type'] == 'IPV4'])
            url_dfs.append(temp_df[temp_df['Type'] == 'URL'])
            md5_dfs.append(temp_df[temp_df['Type'] == 'MD5'])
        elif ".xlsx" in full_filename:
            temp_df = pd.read_excel(file_path)
            # type 2
            if 'uuid' in temp_df.columns:
                # create Published and Updated columns from modified date
                temp_df['Published'] = temp_df['date'].apply(lambda x: date.fromtimestamp(x).isoformat())
                temp_df['Updated'] = temp_df['date'].apply(lambda x: date.fromtimestamp(x).isoformat())
                # need to replace NaN's (NONE in pandas) with empty strings to concatenate
                temp_df.fillna('', inplace=True)
                # create Context column from the filename, event_id, comment, and attribute_tag
                filename, ext = os.path.splitext(full_filename)
                temp_df.loc[temp_df['comment'] != '', 'Context'] = filename + ': ' + 'Comment=' + temp_df['comment'] + '; event_id=' + temp_df['event_id'].astype(str) + '; attribute_tag=' + temp_df['attribute_tag']
                temp_df.loc[temp_df['comment'] == '', 'Context'] = filename + ': ' + 'event_id=' + temp_df['event_id'].astype(str) + '; attribute_tag=' + temp_df['attribute_tag']
                # drop unnecessary columns
                unnecessary_columns = ['uuid', 'event_id', 'comment', 'attribute_tag', 'category', 'to_ids', 'object_relation', 'object_uuid', 'object_name', 'object_meta_category', 'date']
                temp_df.drop(unnecessary_columns, axis=1, inplace=True)
                # rename columns
                temp_df.columns = ['Type', 'Indicator', 'Published', 'Updated', 'Context']
                # reorder columns
                temp_df = temp_df[['Indicator', 'Type', 'Published', 'Updated', 'Context']]
                dns_dfs.append(temp_df[temp_df['Type'] == 'domain'])
                # strip port number from ip address 
                temp_df['Indicator'] = temp_df['Indicator'].apply(lambda x: x if '|' not in x else x.split('|')[0])
                ip_dfs.append(temp_df[temp_df['Type'] == 'ip-dst|port'])
                url_dfs.append(temp_df[temp_df['Type'] == 'url'])
                md5_dfs.append(temp_df[temp_df['Type'] == 'md5'])
                sha256_dfs.append(temp_df[temp_df['Type'] == 'sha256'])
            # type 1
            else:
                # need to replace NaN's (NONE in pandas) with empty strings to concatenate
                temp_df.fillna('', inplace=True)
                # create Context column from the filename, event_id, comment, and attribute_tag
                filename, ext = os.path.splitext(full_filename)
                temp_df['Context'] = filename
                # use last modified time as Published and Updated values
                time = date.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                temp_df['Published'] = time
                temp_df['Updated'] = time
                # dummy column for consistency
                temp_df['Type'] = ''
                if 'Domains' in temp_df.columns:
                    step_df = temp_df[['Domains', 'Type', 'Published', 'Updated', 'Context']]
                    step_df.rename(columns = {'Domains':'Indicator'}, inplace=True)
                    dns_dfs.append(step_df)
                if 'IP Addresses' in temp_df.columns:
                    step_df = temp_df[['IP Addresses', 'Type', 'Published', 'Updated', 'Context']]
                    step_df.rename(columns = {'IP Addresses':'Indicator'}, inplace=True)
                    ip_dfs.append(step_df)
                if 'URLs' in temp_df.columns:
                    step_df = temp_df[['URLs', 'Type', 'Published', 'Updated', 'Context']]
                    step_df.rename(columns = {'URLs':'Indicator'}, inplace=True)
                    url_dfs.append(step_df)
                if 'Hashes' in temp_df.columns:
                    temp_df['md5'] = temp_df['Hashes'].apply(lambda x: x if len(x) == 32 else '')
                    temp_df['sha1'] = temp_df['Hashes'].apply(lambda x: x if len(x) == 40 else '')
                    temp_df['sha256'] = temp_df['Hashes'].apply(lambda x: x if len(x) == 64 else '')

                    step_df = temp_df[['md5', 'Type', 'Published', 'Updated', 'Context']]
                    step_df = step_df[step_df['md5'].astype(bool)].copy()
                    step_df.rename(columns = {'md5':'Indicator'}, inplace=True)
                    #print(step_df)
                    md5_dfs.append(step_df)

                    step_df = temp_df[['sha1', 'Type', 'Published', 'Updated', 'Context']]
                    step_df = step_df[step_df['sha1'].astype(bool)].copy()
                    step_df.rename(columns = {'sha1':'Indicator'}, inplace=True)
                    #print(step_df)
                    sha1_dfs.append(step_df)

                    step_df = temp_df[['sha256', 'Type', 'Published', 'Updated', 'Context']]
                    step_df = step_df[step_df['sha256'].astype(bool)].copy()
                    step_df.rename(columns = {'sha256':'Indicator'}, inplace=True)
                    #print(step_df)
                    sha256_dfs.append(step_df)
                if 'Email Addresses' in temp_df.columns:
                    step_df = temp_df[['Email Addresses', 'Type', 'Published', 'Updated', 'Context']]
                    step_df.rename(columns = {'Email Addresses':'Indicator'}, inplace=True)
                    email_dfs.append(step_df)

# use command line argument as out path or use script location
if args.out_path:
    out_path = args.out_path
else:
    out_path = args.path

# have to check if list of dfs is empty because .concat will throw error
# deduplicate
# write out to csv
if dns_dfs:
    dns_df = pd.concat(dns_dfs)
    dns_df.drop(['Type'], axis=1, inplace=True)
    #print(dns_df)
    dns_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    dns_df.to_csv(os.path.join(out_path, 'dns_all.csv'), index = False)
if ip_dfs:
    ip_df = pd.concat(ip_dfs)
    ip_df.drop(['Type'], axis=1, inplace=True)
    #print(ip_df)
    ip_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    ip_df.to_csv(os.path.join(out_path, 'ip_all.csv'), index = False)
if url_dfs:
    url_df = pd.concat(url_dfs)
    url_df.drop(['Type'], axis=1, inplace=True)
    #print(url_df)
    url_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    url_df.to_csv(os.path.join(out_path, 'url_all.csv'), index = False)
if md5_dfs:
    md5_df = pd.concat(md5_dfs)
    md5_df.drop(['Type'], axis=1, inplace=True)
    #print(md5_df)
    md5_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    md5_df.to_csv(os.path.join(out_path, 'md5_all.csv'), index = False)

    # write loki format
    with open(os.path.join(out_path, 'md5_all.csv'), 'r') as in_file:
        with open(os.path.join(out_path, 'pre_loki.txt'), 'w') as file:
            rows = csv.DictReader(in_file, fieldnames=['Indicator', 'Published', 'Updated', 'Context'])
            for row in rows:
                if row['Context']:
                    file.write(row['Indicator'] + ';' + row['Context'] + ', ' + 'Downloaded: ' + row['Published'] + '\n')
                else:
                    file.write(row['Indicator'] + ';' + 'Downloaded: ' + row['Published'] + '\n')
    
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