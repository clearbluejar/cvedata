import requests
import json
from pathlib import Path
import argparse
import re

from .config import DATA_DIR, CACHE_PATH
from .util import download_extract_zip_to_path
from .__init__ import __version__

REPO_API_BASE_URL = 'https://api.github.com/repos/clearbluejar/cvedata/releases/'
REPO_DOWNLOAD_BASE_URL = 'https://github.com/clearbluejar/cvedata/releases/download/'

REPO_LATEST_REL_INFO = f'{REPO_API_BASE_URL}latest'
REPO_CURRENT_REL_INFO = f"{REPO_API_BASE_URL}tags/v{__version__}"

DATA_NAME = 'cvedata_data.zip'
CACHE_DATA_NAME = 'cvedata_cache.zip'

def download_release_assets():
    """
    Download the release data that corresponds to the release __version__ in __init__.py
    """

    print(f"Downloading release data from: {REPO_CURRENT_REL_INFO}")

    headers = {
        "Accept-Encoding": "gzip, deflate",
    }

    # this can fail with too many API requests
    repo_info = json.loads(requests.get(REPO_CURRENT_REL_INFO).content)

    for asset in repo_info['assets']:
        print(f"Downloading {asset['name']}")

        # switch download URL to avoid api request rate limiting
        download_url = REPO_DOWNLOAD_BASE_URL + asset['name']
        
        print(f"Downloading {download_url}")
        asset_path = Path(DATA_DIR,asset['name'])
        
        asset_path.write_bytes(requests.get(download_url,headers).content)
        
def download_release_data(version=f"v{__version__}"):

    assert re.search(r'^v\d+(\.\d+){2,3}$', version) is not None

    url = f"{REPO_DOWNLOAD_BASE_URL}{version}/{DATA_NAME}"
    
    print(f"Downloading release data from: {url}")

    download_extract_zip_to_path(url,DATA_DIR)

def download_cache_data(version=f"v{__version__}"):

    assert re.search(r'^v\d+(\.\d+){2,3}$', version) is not None

    url = f"{REPO_DOWNLOAD_BASE_URL}{version}/{CACHE_DATA_NAME}"

    print(f"Downloading release cache data from: {url}")

    download_extract_zip_to_path(url,CACHE_PATH)  


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Download cvedata data')
    
    parser.add_argument('--latest',  action='store_true', help='Download latest data ignoring current package version.')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--data-only',  action='store_true', help='Only download CVE data')
    group.add_argument('--cache-only',  action='store_true', help='Only download CVE cache data')
    
    args = parser.parse_args()

    ver = None

    if args.latest:

        # this can fail with too many API requests
        repo_info = json.loads(requests.get(REPO_LATEST_REL_INFO).content)
        
        ver = repo_info['tag_name']

        if not args.cache_only:
            download_release_data(ver)
        if not args.data_only:
            download_cache_data(ver)
    else:
        if not args.cache_only:
            download_release_data()
        if not args.data_only:
            download_cache_data()