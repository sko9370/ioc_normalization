import pandas as pd
import csv

def add_source(temp_df):
    temp_df['Source'] = temp_df['reporter'].copy()

def add_attribution(temp_df):
    #temp_df['Attribution'] = temp_df['tags'] + '; Confidence: ' + temp_df['confidence_level'].to_string() + '; ref: ' + temp_df['reference']
    temp_df['Attribution'] = temp_df['tags']

def rename_cols(temp_df):
    temp_df.rename(columns = {'ioc_value':'Indicator', 'ioc_type':'Type', '# "first_seen_utc"':'Published', 'last_seen_utc':'Updated'}, inplace=True)
    temp_df['Updated'] = temp_df['Published'].copy()

def drop_cols(temp_df):
    unnecessary_columns = ['ioc_id', 'threat_type', 'fk_malware', 'malware_alias', 'malware_printable', 'confidence_level', 'anonymous', 'reporter', 'reference', 'tags']
    temp_df.drop(unnecessary_columns, axis=1, inplace=True)

def reorder_cols(temp_df):
    return temp_df[['Indicator', 'Type', 'Published', 'Updated', 'Attribution', 'Source']]

def get_domains(temp_df):
    return temp_df[temp_df['Type'] == 'domain'].copy()

def get_ips(temp_df):
    return temp_df[temp_df['Type'] == 'ip:port'].copy()

def get_urls(temp_df):
    return temp_df[temp_df['Type'] == 'url'].copy()

def get_md5s(temp_df):
    return temp_df[temp_df['Type'] == 'md5_hash'].copy()

def get_sha1s(temp_df):
    return temp_df[temp_df['Type'] == 'sha1_hash'].copy()

def get_sha256s(temp_df):
    return temp_df[temp_df['Type'] == 'sha256_hash'].copy()

# end up with Indicator, Type, Published, Updated, Attribution, Source
def preprocess(in_file):
    temp_df = pd.read_csv(in_file, skiprows=8, skipfooter=1, sep=',', quotechar='"', skipinitialspace=True, quoting=csv.QUOTE_ALL, engine='python')
    temp_df.fillna('', inplace=True)
    add_source(temp_df)
    add_attribution(temp_df)
    rename_cols(temp_df)
    drop_cols(temp_df)
    temp_df = reorder_cols(temp_df).copy()
    return temp_df