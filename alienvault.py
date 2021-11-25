import utils
import os

def header():
    return "\"Indicator type\",\"Indicator\",\"Description\""

# must pass format [attribution]_[source]_[date].csv
def parse_filename(full_filename):
    attribution = ''
    attribution, source, end = full_filename.split('_')
    date_field, ext = os.path.splitext(end)
    return attribution, source, date_field

def add_dates(temp_df, date_field):
    temp_df['Published'] = date_field
    temp_df['Updated'] = date_field

def add_source(temp_df, source):
    temp_df['Source'] = source

def add_attribution(temp_df, attribution):
    temp_df.loc[temp_df['Description'] == '', 'Attribution'] = attribution 
    temp_df.loc[temp_df['Description'] != '', 'Attribution'] = attribution + ': ' + temp_df['Description']

def drop_cols(temp_df):
    temp_df.drop(['Description'], axis=1, inplace=True)

def rename_cols(temp_df):
    temp_df.rename(columns = {'Indicator type':'Type'}, inplace=True)

def reorder_cols(temp_df):
    return temp_df[['Indicator', 'Type', 'Published', 'Updated', 'Attribution', 'Source']]

def get_domains(temp_df):
    return temp_df[temp_df['Type'] == 'domain']

def get_hostnames(temp_df):
    return temp_df[temp_df['Type'] == 'hostname']

def get_ips(temp_df):
    return temp_df[temp_df['Type'] == 'IPv4']

def get_urls(temp_df):
    return temp_df[temp_df['Type'] == 'URL']

def get_md5s(temp_df):
    return temp_df[temp_df['Type'] == 'FileHash-MD5']