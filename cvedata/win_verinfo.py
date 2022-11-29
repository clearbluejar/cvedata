from pathlib import Path
import time
import json
import requests
import gzip
import pandas as pd

from .config import DATA_DIR, CACHE_PATH
from .metadata import update_metadata, should_update
from .util import get_file_json

# generated with powershell on Windows
# $ver = [System.Environment]::OSVersion.Version -join '.'
# $path = "${ver}-versioninfo-system32.json"
# Get-ChildItem "C:\Windows\system32\*" -Include "*.dll","*.exe" | select  Name,VersionInfo |ConvertTo-Json -Compress -depth 100 | Out-File $path


WIN10_VERINFO = ['10.0.22621.0', "10.0.22621.0-versioninfo-system32.json"]
WIN2022_VERINFO = ['10.0.20348.0', "10.0.20348.0-versioninfo-system32-winprogiles-recurse.json"]
WIN10_O365 = ['10.0.19045.0', "10.0.19045.0-versioninfo-system32-winprogiles-recurse-o365-compress.json"]
WIN2022_VERINFO_ROLES = ['10.0.20348.0-roles', "10.0.20348.0-versioninfo-system32-winprogiles-recurse-serv2022-roles.json"]

VERINFO_SOURCES = [ WIN10_VERINFO, WIN2022_VERINFO, WIN10_O365, WIN2022_VERINFO_ROLES ]

WINVERINOF_REL_URL = f"https://github.com/clearbluejar/win-sys32-versioninfo/releases/download/v0.1.0/"


VERINFO_DESC_TO_BINS_PATH = Path(DATA_DIR,"win-versioninfo-system32-desc-to-bins.json")
ALL_VERINFO_PATH = Path(DATA_DIR,"win-verinfo-system32-full.json.gz")



def create_win_verinfo():

    verinfo_dfs = []

    all_verinfo_df = pd.DataFrame()


    if should_update(ALL_VERINFO_PATH,1):

        for source in VERINFO_SOURCES:

            name = source[0]
            url = WINVERINOF_REL_URL + source[1]
            
            source_cache_path = Path(CACHE_PATH,  source[1] + '.gz') 
    
            if should_update(source_cache_path,1):            

                print(f"Downloading {url}")
            
                res = requests.get(url)

                assert res.status_code == 200

                with gzip.GzipFile(source_cache_path,'w') as f:
                    f.write(res.content)


            with gzip.GzipFile(source_cache_path, 'r') as f: 
                ver_info = json.loads(f.read())
    
            verinfo_df = pd.json_normalize(ver_info)

            # assign source
            verinfo_df['source'] = name

            # drop repetitive data
            drop_columns = [
                'VersionInfo.ProductBuildPart', 'VersionInfo.ProductMajorPart',
                'VersionInfo.ProductMinorPart', 'VersionInfo.ProductPrivatePart',
                'VersionInfo.FileVersionRaw.Major', 'VersionInfo.FileVersionRaw.Minor',
                'VersionInfo.FileVersionRaw.Build', 'VersionInfo.FileVersionRaw.Revision',
                'VersionInfo.FileVersionRaw.MajorRevision', 'VersionInfo.FileVersionRaw.MinorRevision',
                'VersionInfo.ProductVersionRaw.Major', 'VersionInfo.ProductVersionRaw.Minor',
                'VersionInfo.ProductVersionRaw.Build', 'VersionInfo.ProductVersionRaw.Revision',
                'VersionInfo.ProductVersionRaw.MajorRevision', 'VersionInfo.ProductVersionRaw.MinorRevision']

            verinfo_df.drop(columns=drop_columns,inplace=True)

            print(verinfo_df.head())
            print(verinfo_df.columns)

            verinfo_dfs.append(verinfo_df)

        all_verinfo_df = pd.concat(verinfo_dfs)

        all_verinfo_df = all_verinfo_df.groupby(by=['Name']).aggregate(lambda x: list(set(x)))        

        all_verinfo_df.to_json(ALL_VERINFO_PATH,)
    else:
        print(f"Loading cached {ALL_VERINFO_PATH}")

    all_verinfo_df = pd.read_json(ALL_VERINFO_PATH)
    print(all_verinfo_df.head())
    print(f"all_verinfo_df len {all_verinfo_df.shape[0]}")

def create_win_verinfo_desc_to_bins():

    desc_to_bin_df = pd.read_json(ALL_VERINFO_PATH)
    desc_to_bin_df.index.name = 'Name'
    desc_to_bin_df.reset_index(inplace=True)
    desc_to_bin_df = desc_to_bin_df[['Name','VersionInfo.FileDescription', 'source']]
    print(desc_to_bin_df.head())
    
    # flatten FileDescription
    desc_to_bin_df['VersionInfo.FileDescription'] = desc_to_bin_df['VersionInfo.FileDescription'].apply(lambda x: x[0])    
    
    desc_to_bin_df = desc_to_bin_df.groupby('VersionInfo.FileDescription').aggregate(list)
    desc_to_bin_df.index.name = 'FileDescription'
    # drop empty data
    desc_to_bin_df.drop(labels=['', ' ', '.'],axis=0,inplace=True, errors='ignore')
    desc_to_bin_df['Name'].to_json(VERINFO_DESC_TO_BINS_PATH)
    print(desc_to_bin_df['Name'].head())
    print(f"desc_to_bin_df len {desc_to_bin_df.shape[0]}")

def get_win_ver_info_json():
    return get_file_json(ALL_VERINFO_PATH,__file__)

def get_verinfo_desc_to_bins_json():
    return get_file_json(VERINFO_DESC_TO_BINS_PATH,__file__)

def update():



    print(f"Updating {ALL_VERINFO_PATH}...")
    
    start = time.time()
    create_win_verinfo()
    elapsed = time.time() - start
    
    count = len(get_win_ver_info_json())
    update_metadata(ALL_VERINFO_PATH,{'sources': [WINVERINOF_REL_URL + source[1] for source in VERINFO_SOURCES] },count,elapsed,swap_axes=False,normalize=False)

    print(f"Updating {VERINFO_DESC_TO_BINS_PATH}...")
    
    start = time.time()
    create_win_verinfo_desc_to_bins()
    elapsed = time.time() - start
    
    count = len(get_win_ver_info_json())
    update_metadata(VERINFO_DESC_TO_BINS_PATH,{'sources': [WINVERINOF_REL_URL + source[1] for source in VERINFO_SOURCES] },count,elapsed,swap_axes=True,normalize=True)

if __name__ == "__main__":
    update()