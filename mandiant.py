import utils
from datetime import datetime

def header():
    return "\"Indicator Value\",\"Indicator Type\",\"Associations\",\"Exclusive\",\"First Seen\",\"Last Seen\""

def add_dates(temp_df):
    temp_df['Published'] = temp_df['Published'].apply(lambda x: datetime.strptime(x, '%B %d, %Y').strftime('%Y-%m-%d'))
    temp_df['Updated'] = temp_df['Updated'].apply(lambda x: datetime.strptime(x, '%B %d, %Y').strftime('%Y-%m-%d'))

def add_source(temp_df):
    temp_df['Source'] = 'Mandiant FireEye' 

def drop_cols(temp_df):
    unnecessary_columns = ['Exclusive']
    temp_df.drop(unnecessary_columns, axis=1, inplace=True)

def rename_cols(temp_df):
    temp_df.columns = ['Indicator', 'Type', 'Attribution', 'Published', 'Updated']

def reorder_cols(temp_df):
    return temp_df[['Indicator', 'Type', 'Published', 'Updated', 'Attribution', 'Source']]

def get_domains(temp_df):
    return temp_df[temp_df['Type'] == 'FQDN']

def get_ips(temp_df):
    return temp_df[temp_df['Type'] == 'IPV4']

def get_urls(temp_df):
    return temp_df[temp_df['Type'] == 'URL']

def get_md5s(temp_df):
    return temp_df[temp_df['Type'] == 'MD5']

def get_sha1s(temp_df):
    return temp_df[temp_df['Type'] == 'SHA1']

def get_sha256s(temp_df):
    return temp_df[temp_df['Type'] == 'SHA256']

def preprocess(in_file):
    temp_df = utils.read_csv(in_file)
    drop_cols(temp_df)
    rename_cols(temp_df)
    add_source(temp_df)
    temp_df = reorder_cols(temp_df)
    add_dates(temp_df)
    return temp_df