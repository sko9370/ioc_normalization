import utils
import os

def header():
    return "indicator,type,malware_families,actors,reports,kill_chains,published_date,last_updated,malicious_confidence,labels"

def add_dates(temp_df):
    # format datetime into just date YYYY-MM-DD
    temp_df['Published'] = temp_df['Published'].apply(lambda x: x[:10])
    temp_df['Updated'] = temp_df['Updated'].apply(lambda x: x[:10])

def add_source(temp_df):
    temp_df['Source'] = 'Crowdstrike' 

def add_attribution(temp_df):
    temp_df.loc[(temp_df['malware_families'] != '') & (temp_df['actors'] != ''), 'Attribution'] = 'Actors(s): ' + temp_df['actors'] + '; Malware: ' + temp_df['malware_families']
    temp_df.loc[temp_df['malware_families'] == '', 'Attribution'] = 'Actors(s): ' + temp_df['actors']
    temp_df.loc[temp_df['actors'] == '', 'Attribution'] = 'Malware: ' + temp_df['malware_families']

def drop_cols(temp_df):
    unnecessary_columns = ['reports','kill_chains','malicious_confidence', 'labels', 'actors', 'malware_families']
    temp_df.drop(unnecessary_columns, axis=1, inplace=True)

def rename_cols(temp_df):
    temp_df.rename(columns = {'indicator':'Indicator', 'type':'Type', 'published_date':'Published', 'last_updated':'Updated'}, inplace=True)

def reorder_cols(temp_df):
    return temp_df[['Indicator', 'Type', 'Published', 'Updated', 'Attribution', 'Source']]

def get_domains(temp_df):
    return temp_df[temp_df['Type'] == 'domain']

def get_ips(temp_df):
    return temp_df[temp_df['Type'] == 'ip_address']

def get_urls(temp_df):
    return temp_df[temp_df['Type'] == 'url']

def get_md5s(temp_df):
    return temp_df[temp_df['Type'] == 'hash_md5']

def preprocess(in_file):
    temp_df = utils.read_csv(in_file)
    # need to replace NaN's (NONE in pandas) with empty strings to concatenate
    utils.fill_empty(temp_df)
    add_source(temp_df)
    add_attribution(temp_df)
    drop_cols(temp_df)
    rename_cols(temp_df)
    add_dates(temp_df)
    temp_df = reorder_cols(temp_df)
    return temp_df