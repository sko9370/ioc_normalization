import os
import pandas as pd

def get_file_paths(topdir):
    extensions = ['.csv', '.xlsx']
    if topdir.endswith(extensions[0]) or topdir.endswith(extensions[1]):
        return [topdir]
    file_paths = []
    for dirpath, dirnames, files in os.walk(topdir):
        for name in files:
            if name.lower().endswith(extensions[0]):
                file_paths.append(os.path.join(dirpath, name))
            elif name.lower().endswith(extensions[1]):
                file_paths.append(os.path.join(dirpath, name))
    return file_paths

def read_csv(in_file):
    return pd.read_csv(in_file, header=0, dtype='unicode')

def fill_empty(temp_df):
    temp_df.fillna('', inplace=True)