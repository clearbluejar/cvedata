import requests
import json
from pathlib import Path

from .config import DATA_DIR, CACHE_PATH, REPO_REL_VERSION_INFO, REPO_REL_DOWNLOAD_URL
from .util import download_extract_zip_to_path

RELEASE_DATA_DOWNLOAD_INFO = { 'url': REPO_REL_DOWNLOAD_URL + 'cvedata_data.zip', 'path': DATA_DIR }
CACHE_DATA_DOWNLOAD_INFO = { 'url': REPO_REL_DOWNLOAD_URL + 'cvedata_cache.zip', 'path': CACHE_PATH }

def download_release_assets():
    """
    Download the release data that corresponds to the release __version__ in __init__.py
    """

    print(f"Downloading release data from: {REPO_REL_VERSION_INFO}")

    headers = {
        "Accept-Encoding": "gzip, deflate",    
    }

    # this can fail with too many API requests
    repo_info = json.loads(requests.get(REPO_REL_VERSION_INFO).content)

    for asset in repo_info['assets']:
        print(f"Downloading {asset['name']}")

        # switch download URL to avoid api request rate limiting
        download_url = REPO_REL_DOWNLOAD_URL + asset['name']
        
        print(f"Downloading {download_url}")
        asset_path = Path(DATA_DIR,asset['name'])
        
        asset_path.write_bytes(requests.get(download_url,headers).content)
        
def download_release_data():

    print(f"Downloading release data from: {RELEASE_DATA_DOWNLOAD_INFO['url']}")

    download_extract_zip_to_path(RELEASE_DATA_DOWNLOAD_INFO['url'],RELEASE_DATA_DOWNLOAD_INFO['path'])

def download_cache_data():

    print(f"Downloading release data from: {CACHE_DATA_DOWNLOAD_INFO['url']}")

    download_extract_zip_to_path(CACHE_DATA_DOWNLOAD_INFO['url'],CACHE_DATA_DOWNLOAD_INFO['path'])

if __name__ == "__main__":
    download_release_data()
    download_cache_data()