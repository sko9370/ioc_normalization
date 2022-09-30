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
import threatfox

# parses command line for path argument
parser = argparse.ArgumentParser()
parser.add_argument('-p', '--path', type=str, help='Specify target path of IOC CSVs')
parser.add_argument('-o', '--out_path', type=str, help='Specify output file path')
args, commands = parser.parse_known_args()

if not args.path:
    print('Must provide input CSVs\' path using -p')
    sys.exit(1)

# expecting top level directory with sub-directories named according to source
# alienvault (av), mandiant (md), crowdstrike (cs), threatfox (tf)
av_files, md_files, cs_files, tf_files, ct_files = utils.get_file_paths(args.path)

# list of dataframes to be merged at the end
dns_dfs = []
ip_dfs = []
url_dfs = []
md5_dfs = []
sha1_dfs = []
sha256_dfs = []
email_dfs = []
ja3_dfs = []

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
    # does this change in place?
    temp_df.loc[:, ['Indicator', 'Type', 'Updated', 'Attribution', 'Source']]
    print(temp_df)