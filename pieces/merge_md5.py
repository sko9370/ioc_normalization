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

# create list of dataframes
for file in file_paths:
    dfs.append(pd.read_csv(file, index_col=0, dtype='unicode'))

# take list of dataframes and merge together using pd.concat([list of dfs])
df = pd.concat(dfs)

df.columns.names = ['Indicator']
df.index.name = 'Indicator'

# use command line argument as out path or use script location
if args.out_path:
    out_path = args.out_path
else:
    out_path = args.path

# deduplicate
# doesn't work
#df.drop_duplicates(subset=['Indicator'], keep='last', inplace=True)

# slightly faster than drop_duplicates method
df = df[~df.index.duplicated(keep='last')]

df.to_csv(os.path.join(out_path, 'md5_all_dedup.csv'))