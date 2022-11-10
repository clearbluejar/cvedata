from pathlib import Path
import time
import json
import requests
import gzip
import pandas as pd

from .config import DATA_DIR, CACHE_PATH
from .metadata import update_metadata
from .util import get_file_json

# generated with powershell on Windows
# $ver = [System.Environment]::OSVersion.Version -join '.'
# $path = "${ver}-versioninfo-system32.json"
# Get-ChildItem "C:\Windows\system32\*" -Include "*.dll","*.exe" | select  Name,VersionInfo |ConvertTo-Json -Compress -depth 100 | Out-File $path


WIN_VERINFO_NAME = "10.0.22621.0-versioninfo-system32.json"
WIN10_SYS32_VERINFO_JSON_PATH = Path(CACHE_PATH , WIN_VERINFO_NAME + '.gz')
WIN10_SYS32_VERINFO_URL = f"https://github.com/clearbluejar/win-sys32-versioninfo/releases/download/v0.1.0/{WIN_VERINFO_NAME}"
VERINFO_DESC_TO_BINS_PATH = Path(DATA_DIR,"versioninfo-system32-desc-to-bins.json")
VERINFO_PATH = Path(DATA_DIR,"versioninfo-system32-full.json.gz")

def create_win_verinfo():

    if WIN10_SYS32_VERINFO_JSON_PATH.exists():
        print(f"Loading cached {WIN10_SYS32_VERINFO_JSON_PATH}")
        with gzip.GzipFile(WIN10_SYS32_VERINFO_JSON_PATH) as f:
            ver_info = json.load(f)
    else:
        print(f"Downloading {WIN10_SYS32_VERINFO_URL}")
        
        res = requests.get(WIN10_SYS32_VERINFO_URL)

        assert res.status_code == 200

        ver_info = json.loads(res.content)

        with gzip.GzipFile(WIN10_SYS32_VERINFO_JSON_PATH,'w') as f:
            f.write(json.dumps(ver_info).encode("utf-8"))
    
    verinfo_df = pd.json_normalize(ver_info)

    print(verinfo_df.columns)

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
    
    verinfo_df.to_json(VERINFO_PATH)

    print(verinfo_df.head())

def create_win_verinfo_desc_to_bins():

    verinfo_df = pd.read_json(VERINFO_PATH)
    desc_to_bin_df = verinfo_df[['Name','VersionInfo.FileDescription']]
    desc_to_bin_df = desc_to_bin_df.groupby('VersionInfo.FileDescription').aggregate(list)
    desc_to_bin_df['Name'].to_json(VERINFO_DESC_TO_BINS_PATH)
    print(desc_to_bin_df['Name'].head())

def get_win_ver_info_json():
    return get_file_json(VERINFO_PATH,__file__)

def get_verinfo_desc_to_bins_json():
    return get_file_json(VERINFO_DESC_TO_BINS_PATH,__file__)

def update():

    print(f"Updating {VERINFO_PATH}...")
    
    start = time.time()
    create_win_verinfo()
    elapsed = time.time() - start
    
    count = len(get_win_ver_info_json())
    update_metadata(VERINFO_PATH,{'sources': ['C:\\Windows\\System32']},count,elapsed,swap_axes=False)

    print(f"Updating {VERINFO_DESC_TO_BINS_PATH}...")
    
    start = time.time()
    create_win_verinfo_desc_to_bins()
    elapsed = time.time() - start
    
    count = len(get_win_ver_info_json())
    update_metadata(VERINFO_DESC_TO_BINS_PATH,{'sources': ['C:\\Windows\\System32']},count,elapsed,swap_axes=False)

if __name__ == "__main__":
    update()