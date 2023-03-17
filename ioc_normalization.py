import argparse
import os, sys
import csv
import pandas as pd
import requests
from io import StringIO, BytesIO
from zipfile import ZipFile
from datetime import datetime
from datetime import date
from urllib.parse import urlparse

# parses command line for path argument
parser = argparse.ArgumentParser()
parser.add_argument('-p', '--path', type=str, help='Specify target path of IOC CSVs')
parser.add_argument('-o', '--out_path', type=str, help='Specify output file path')
args, commands = parser.parse_known_args()

if not args.path:
    print('Must provide input CSVs\' path using -p')
    sys.exit(1)

# set output path
if args.out_path:
    out_path = args.out_path
else:
    out_path = args.path

# expecting top level directory with sub-directories named according to source
# alienvault (av), mandiant (md), crowdstrike (cs), threatfox (tf)
def get_file_paths(topdir):
    av_files = []
    md_files = []
    cs_files = []
    tf_files = []
    ct_files = []
    og_files = []
    for dirpath, dirnames, files in os.walk(topdir):
        for name in files:
            if name.lower().endswith('csv'):
                if 'alienvault' in dirpath:
                    av_files.append(os.path.join(dirpath, name))
                elif 'mandiant' in dirpath:
                    md_files.append(os.path.join(dirpath, name))
                elif 'crowdstrike' in dirpath:
                    cs_files.append(os.path.join(dirpath, name))
                elif 'threatfox' in dirpath:
                    tf_files.append(os.path.join(dirpath, name))
                elif 'custom' in dirpath:
                    ct_files.append(os.path.join(dirpath, name))
                elif 'old' in dirpath:
                    og_files.append(os.path.join(dirpath,name))
    return av_files, md_files, cs_files, tf_files, ct_files, og_files

print('1/3: Categorizing files')
av_files, md_files, cs_files, tf_files, ct_files, og_files = get_file_paths(args.path)

# list of dataframes to be merged at the end
dns_dfs = []
ip_dfs = []
url_dfs = []
md5_dfs = []
sha1_dfs = []
sha256_dfs = []
email_dfs = []
ja3_dfs = []

print('2/3: Begin processing files')

### AlienVault processing ###
# must pass format [attribution]_[source]_[date].csv
def parse_filename(full_filename):
    attribution = ''
    attribution, source, end = full_filename.split('_')
    date_field, ext = os.path.splitext(end)
    return attribution, source, date_field
for filepath in av_files:
    # get filename from filepath
    filename = os.path.basename(filepath)
    # get additional fields from filename since AlienVault CSVs only have 3 fields
    attribution, source, date_field = parse_filename(filename)
    # read in CSV at filepath as a dataframe
    temp_df = pd.read_csv(filepath, header=0, dtype='unicode')
    temp_df.fillna('', inplace=True)
    # add attribution field based on filename
    # uses loc to return boolean based series and specifies new column name
    # https://pandas.pydata.org/docs/reference/api/pandas.DataFrame.loc.html
    temp_df.loc[temp_df['Description'] == '', 'Attribution'] = attribution 
    temp_df.loc[temp_df['Description'] != '', 'Attribution'] = attribution + ': ' + temp_df['Description']
    # add date field based on filename
    temp_df['Updated'] = date_field
    # add source field based on filename
    temp_df['Source'] = source
    # drop Description column
    temp_df.drop(['Description'], axis=1, inplace=True)
    # rename columns
    temp_df.rename(columns = {'Indicator type':'Type'}, inplace=True)
    # reorder columns
    temp_df = temp_df[['Indicator', 'Type', 'Updated', 'Attribution', 'Source']].copy()
    # add IOCs to dataframe lists by type
    dns_dfs.append(temp_df[temp_df['Type'] == 'domain'].copy())
    dns_dfs.append(temp_df[temp_df['Type'] == 'hostname'].copy())
    ip_dfs.append(temp_df[temp_df['Type'] == 'IPv4'].copy())
    url_dfs.append(temp_df[temp_df['Type'] == 'URL'].copy())
    md5_dfs.append(temp_df[temp_df['Type'] == 'FileHash-MD5'].copy())
    sha1_dfs.append(temp_df[temp_df['Type'] == 'FileHash-SHA1'].copy())
    sha256_dfs.append(temp_df[temp_df['Type'] == 'FileHash-SHA256'].copy())
    email_dfs.append(temp_df[temp_df['Type'] == 'email'].copy())
### CrowdStrike processing ###
for filepath in cs_files:
    # get filename from filepath
    filename = os.path.basename(filepath)
    # read in CSV at filepath as a dataframe
    temp_df = pd.read_csv(filepath, header=0, dtype='unicode')
    temp_df.fillna('', inplace=True)
    # add attribution by parsing actors and malware_families column
    temp_df.loc[(temp_df['malware_families'] != '') & (temp_df['actors'] != ''), 'Attribution'] = 'Actors(s): ' + temp_df['actors'] + '; Malware: ' + temp_df['malware_families']
    # assume all IOCs are linked to either an actor or malware family
    temp_df.loc[temp_df['malware_families'] == '', 'Attribution'] = 'Actors(s): ' + temp_df['actors']
    temp_df.loc[temp_df['actors'] == '', 'Attribution'] = 'Malware: ' + temp_df['malware_families']
    # drop unnecessary columns
    unnecessary_columns = ['reports','kill_chains','malicious_confidence', 'labels', 'actors', 'malware_families', 'published_date']
    temp_df.drop(unnecessary_columns, axis=1, inplace=True)
    # rename columns
    temp_df.rename(columns = {'indicator':'Indicator', 'type':'Type', 'last_updated':'Updated'}, inplace=True)
    # add dates field parsed
    temp_df['Updated'] = temp_df['Updated'].apply(lambda x: x[:10])
    # add source field
    temp_df['Source'] = "CrowdStrike"
    # reorder columns
    temp_df = temp_df[['Indicator', 'Type', 'Updated', 'Attribution', 'Source']].copy()
    # add IOCs to dataframe lists by type
    dns_dfs.append(temp_df[temp_df['Type'] == 'domain'].copy())
    ip_dfs.append(temp_df[temp_df['Type'] == 'ip_address'].copy())
    url_dfs.append(temp_df[temp_df['Type'] == 'url'].copy())
    md5_dfs.append(temp_df[temp_df['Type'] == 'hash_md5'].copy())
    sha1_dfs.append(temp_df[temp_df['Type'] == 'hash_sha1'].copy())
    sha256_dfs.append(temp_df[temp_df['Type'] == 'hash_sha256'].copy())
    email_dfs.append(temp_df[temp_df['Type'] == 'email_address'].copy())
### Mandiant processing ###
for filepath in md_files:
    # read in CSV at filepath as a dataframe
    temp_df = pd.read_csv(filepath, header=0, dtype='unicode')
    temp_df.fillna('', inplace=True)
    # drop unnecessary columns
    unnecessary_columns = ['Exclusive', 'First Seen']
    temp_df.drop(unnecessary_columns, axis=1, inplace=True)
    # rename columns
    temp_df.rename(columns = {'Indicator Value':'Indicator', 'Indicator Type':'Type', 'Last Seen':'Updated', 'Associations':'Attribution'}, inplace=True)
    # add source
    temp_df['Source'] = 'Mandiant FireEye' 
    # reorder columns
    temp_df = temp_df.loc[:,('Indicator', 'Type', 'Updated', 'Attribution', 'Source')]
    # reformat dates
    try:
        temp_df['Updated'] = temp_df['Updated'].apply(lambda x: datetime.strptime(x, '%B %d, %Y').strftime('%Y-%m-%d'))
    except ValueError:
        temp_df['Updated'] = temp_df['Updated'].apply(lambda x: datetime.strptime(x, '%d-%b-%Y').strftime('%Y-%m-%d'))
    # add IOCs to dataframe lists by type
    dns_dfs.append(temp_df[temp_df['Type'] == 'FQDN'].copy())
    ip_dfs.append(temp_df[temp_df['Type'] == 'IPV4'].copy())
    url_dfs.append(temp_df[temp_df['Type'] == 'URL'].copy())
    md5_dfs.append(temp_df[temp_df['Type'] == 'MD5'].copy())
    sha1_dfs.append(temp_df[temp_df['Type'] == 'SHA1'].copy())
    sha256_dfs.append(temp_df[temp_df['Type'] == 'SHA256'].copy())
### Custom Processing ###
for filepath in ct_files:
    # get filename from filepath
    filename = os.path.basename(filepath)
    # read in CSV at filepath as a dataframe
    temp_df = pd.read_csv(filepath, header=0, dtype='unicode')
    temp_df.fillna('', inplace=True)
    # add IOCs to dataframe lists by type
    dns_dfs.append(temp_df[temp_df['Type'] == 'domain'].copy())
    dns_dfs.append(temp_df[temp_df['Type'] == 'hostname'].copy())
    ip_dfs.append(temp_df[temp_df['Type'] == 'IPv4'].copy())
    url_dfs.append(temp_df[temp_df['Type'] == 'URL'].copy())
    md5_dfs.append(temp_df[temp_df['Type'] == 'FileHash-MD5'].copy())
    sha1_dfs.append(temp_df[temp_df['Type'] == 'FileHash-SHA1'].copy())
    sha256_dfs.append(temp_df[temp_df['Type'] == 'FileHash-SHA256'].copy())
    email_dfs.append(temp_df[temp_df['Type'] == 'email'].copy())
### Old processed files ###
for filepath in og_files:
    if 'ip' in filepath:
        temp_df = pd.read_csv(filepath, header=0, dtype='unicode')
        temp_df.insert(1,'Type','')
        ip_dfs.append(temp_df.copy())
    elif 'dns' in filepath:
        temp_df = pd.read_csv(filepath, header=0, dtype='unicode')
        temp_df.insert(1,'Type','')
        dns_dfs.append(temp_df.copy())
    elif 'md5' in filepath:
        temp_df = pd.read_csv(filepath, header=0, dtype='unicode')
        temp_df.insert(1,'Type','')
        md5_dfs.append(temp_df.copy())
    elif 'url' in filepath:
        temp_df = pd.read_csv(filepath, header=0, dtype='unicode')
        temp_df.insert(1,'Type','')
        url_dfs.append(temp_df.copy())
    elif 'sha1' in filepath:
        temp_df = pd.read_csv(filepath, header=0, dtype='unicode')
        temp_df.insert(1,'Type','')
        sha1_dfs.append(temp_df.copy())
    elif 'sha256' in filepath:
        temp_df = pd.read_csv(filepath, header=0, dtype='unicode')
        temp_df.insert(1,'Type','')
        sha256_dfs.append(temp_df.copy())
    elif 'email' in filepath:
        temp_df = pd.read_csv(filepath, header=0, dtype='unicode')
        temp_df.insert(1,'Type','')
        email_dfs.append(temp_df.copy())
### ThreatFox processing ###
try:
    url = 'https://threatfox.abuse.ch/export/csv/full/'
    response = requests.get(url)
    # instantiate zip file in memory and extract just full.csv as z
    with ZipFile(BytesIO(response.content)).open('full.csv') as z:
        threatfox_string = z.read().decode('utf-8')
    tf_io = StringIO(threatfox_string)
    tf_df = pd.read_csv(tf_io, skiprows=8, skipfooter=1, sep=',', quotechar='"', skipinitialspace=True, quoting=csv.QUOTE_ALL, engine='python')
    tf_df.fillna('', inplace=True)
    # add source
    tf_df['Source'] = tf_df['reporter'].copy()
    # add attribution
    tf_df['Attribution'] = tf_df['tags']
    # rename columns
    tf_df.rename(columns = {'ioc_value':'Indicator', 'ioc_type':'Type', '# "first_seen_utc"':'Updated'}, inplace=True)
    # drop columns
    unnecessary_columns = ['ioc_id', 'threat_type', 'fk_malware', 'malware_alias', 'malware_printable', 'confidence_level', 'anonymous', 'reporter', 'reference', 'tags', 'last_seen_utc']
    tf_df.drop(unnecessary_columns, axis=1, inplace=True)
    # reorder columns
    tf_df = tf_df.loc[:, ('Indicator', 'Type', 'Updated', 'Attribution', 'Source')]
    # reformat dates
    tf_df['Updated'] = tf_df['Updated'].apply(lambda x: x[:10])
    # add IOCs to dataframe lists by type
    dns_dfs.append(tf_df[tf_df['Type'] == 'domain'].copy())
    ip_dfs.append(tf_df[tf_df['Type'] == 'ip:port'].copy())
    url_dfs.append(tf_df[tf_df['Type'] == 'url'].copy())
    md5_dfs.append(tf_df[tf_df['Type'] == 'md5_hash'].copy())
    sha1_dfs.append(tf_df[tf_df['Type'] == 'sha1_hash'].copy())
    sha256_dfs.append(tf_df[tf_df['Type'] == 'sha256_hash'].copy())
except:
    print('ThreatFox download failed or rate limit reached, try again in a few minutes')
# add most recent tor exit node list
# https://check.torproject.org/torbulkexitlist
try:
    url = 'https://check.torproject.org/torbulkexitlist'
    response = requests.get(url)
    tor_exit_ips = response.content.decode("utf-8").splitlines()
    tor_df = pd.DataFrame(tor_exit_ips, columns=['Indicator'])
    tor_df['Updated'] = date.today()
    tor_df['Type'] = ''
    tor_df['Attribution'] = 'tor exit node'
    tor_df['Source'] = 'https://check.torproject.org/torbulkexitlist'
    ip_dfs.append(tor_df.copy())
except:
    print('Was not able to access check.torproject.org/torbulkexitlist or process data. Check internet connection.')
# add most recent SSL SHA1 fingerprint list
# https://sslbl.abuse.ch/blacklist/sslblacklist.csv
try:
    url = 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv'
    response = requests.get(url)
    ssl_string = response.content.decode("utf-8")
    ssl_io = StringIO(ssl_string)
    ssl_df = pd.read_csv(ssl_io, skiprows=8, skipfooter=1, sep=',', quotechar='"', skipinitialspace=True, quoting=csv.QUOTE_ALL, engine='python')
    ssl_df.fillna('', inplace=True)
    ssl_df.rename(columns={'# Listingdate':'Updated', 'SHA1':'Indicator', 'Listingreason':'Attribution'}, inplace=True)
    #print(ssl_df.columns)
    ssl_df = ssl_df[['Indicator', 'Updated', 'Attribution']]
    ssl_df['Source'] = 'sslbl.abuse.ch'
    ssl_df['Updated'] = ssl_df['Updated'].apply(lambda x: x[:10])
except:
    print('Was not able to access sslbl.abuse.ch/blacklist/sslblacklist.csv or process data. Check internet connection.')

print('3/3: Begin exporting to CSV')

######################## output dataframes to CSV #########################

if len(ssl_df.index):
    ssl_df.to_csv(os.path.join(out_path, 'ssl_all.csv'), index = False)
if url_dfs:
    # merge all url dataframes from url df list together
    url_df = pd.concat(url_dfs)
    # parse out domains and IPs to add to DNS dataframe and IP dataframe
    parsed_dns_df = url_df.copy()
    parsed_dns_df['Indicator'] = parsed_dns_df['Indicator'].apply(lambda x: urlparse(x).hostname)
    parsed_ip_df = parsed_dns_df.copy()
    parsed_ip_df['Indicator'] = parsed_ip_df['Indicator'].str.extract(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    parsed_ip_df.dropna(inplace=True)
    # add note in source column that parsed out from URLs and high chance of false positive
    parsed_ip_df['Source'] = parsed_ip_df['Source'] + '; LOW CONFIDENCE, PARSED FROM URL IOCS'
    ip_dfs.append(parsed_ip_df)
    # delete all IPs and only send domains
    parsed_dns_df['IP'] = parsed_dns_df['Indicator'].str.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    parsed_dns_df = parsed_dns_df[parsed_dns_df.IP != True]
    parsed_dns_df.drop(['IP'], axis=1, inplace=True)
    parsed_dns_df.dropna(inplace=True)
    # add note in source column that parsed out from URLs and high chance of false positive
    parsed_dns_df['Source'] = parsed_dns_df['Source'] + '; LOW CONFIDENCE, PARSED FROM URL IOCS'
    dns_dfs.append(parsed_dns_df)
    # parse out path and add as new field
    url_df['Path'] = url_df['Indicator'].apply(lambda x: urlparse(x).path)
    url_df = url_df.loc[:,('Indicator', 'Path', 'Type', 'Updated', 'Attribution', 'Source')]
    url_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    # delete empty paths (just '/')
    url_df.loc[url_df['Path'] == '/'] = ''
    # sanity check for empty rows
    url_df = url_df[url_df['Indicator'] != '']
    url_df.to_csv(os.path.join(out_path, 'url_all.csv'), index = False)
if dns_dfs:
    dns_df = pd.concat(dns_dfs)
    dns_df.drop(['Type'], axis=1, inplace=True)
    dns_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    dns_df = dns_df[dns_df['Indicator'] != '']
    # filter out top 100 domains from majestic million whitelist to prevent false positives from url IOCs
    url = 'https://downloads.majestic.com/majestic_million.csv'
    response = requests.get(url)
    csvtext = response.content.decode('utf-8')
    cols = csvtext.split('\n')[0].split(',')
    wl_df = pd.DataFrame([row.split(',') for row in csvtext.split('\n')[1:]], columns=cols)
    # only keep com TLDs
    wl_df = wl_df[wl_df['TLD'] == 'com'].copy()
    #print(wl_df)
    # only keep top 100 domains
    wl_df.drop(wl_df.index[100:], inplace=True)
    wl_df.rename(columns = {'Domain':'Indicator'}, inplace=True)
    # view domain matches against whitelist
    #print(dns_df.merge(wl_df, on='Indicator', how='inner'))
    # left excluding join
    # https://stackoverflow.com/questions/53645882/pandas-merging-101/53645883#53645883
    dns_df = dns_df.merge(wl_df['Indicator'], on='Indicator', how='left', indicator=True).query('_merge == "left_only"').drop(columns=['_merge'], axis=1)
    dns_df.to_csv(os.path.join(out_path, 'dns_all.csv'), index = False)
if ip_dfs:
    ip_df = pd.concat(ip_dfs)
    ip_df.drop(['Type'], axis=1, inplace=True)
    ip_df['Indicator'] = ip_df['Indicator'].str.extract(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    ip_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    ip_df = ip_df[ip_df['Indicator'] != '']
    ip_df.to_csv(os.path.join(out_path, 'ip_all.csv'), index = False)
if md5_dfs:
    md5_df = pd.concat(md5_dfs)
    md5_df.drop(['Type'], axis=1, inplace=True)
    md5_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    md5_df = md5_df[md5_df['Indicator'] != '']
    md5_df.to_csv(os.path.join(out_path, 'md5_all.csv'), index = False)
    with open(os.path.join(out_path, 'hash-custom-loki.txt'), 'w') as file:
        md5_df.loc[md5_df['Attribution'] == '', 'loki'] = md5_df['Indicator'] + '; ' + 'Updated: ' + md5_df['Updated'] + ', ' + 'Source: ' + md5_df['Source']
        md5_df.loc[md5_df['Attribution'] != '', 'loki'] = md5_df['Indicator'] + '; ' + 'Updated: ' + md5_df['Updated'] + ', ' + 'Source: ' + md5_df['Source'] + ', ' + 'Attribution: ' + md5_df['Attribution']
        pd.options.display.max_colwidth = None
        #display(md5_df)
        lines = md5_df['loki'].to_string(header=False, index=False).split('\n')
        for line in lines:
            # need to left align data
            file.write(line.lstrip() + '\n')
if email_dfs:
    email_df = pd.concat(email_dfs)
    email_df.drop(['Type'], axis=1, inplace=True)
    email_df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)
    email_df = email_df[email_df['Indicator'] != '']
    email_df.to_csv(os.path.join(out_path, 'email_all.csv'), index = False)