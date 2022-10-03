import os
import pandas as pd

def get_file_paths(topdir):
    av_files = []
    md_files = []
    cs_files = []
    tf_files = []
    ct_files = []
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
    return av_files, md_files, cs_files, tf_files 