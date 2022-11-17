import requests
import json
from pathlib import Path

from .config import DATA_DIR, REPO_REL_VERSION_INFO, REPO_REL_DOWNLOAD_URL


def download_release_data():
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
        


    

if __name__ == "__main__":
    download_release_data()