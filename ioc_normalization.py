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
av_files, md_files, cs_files, tf_files = utils.get_file_paths(args.path)

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