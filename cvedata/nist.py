from datetime import datetime
import json
import gzip
import requests
import os
import time
from pathlib import Path

import io
from functools import lru_cache

from .config import DATA_DIR, CACHE_PATH
from .metadata import update_metadata
from .util import get_file_json

NIST_CVE_MERGED_PATH = Path(DATA_DIR, 'nist_merged_cve.json.gz')
NIST_DATA_FEEDS_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/"


def download_extract_gz(url):
    """
    Read json file from winbindex
    """
    response = requests.get(url)
    
    # if this fails the data would be incomplete
    assert(response.status_code == 200)

    with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as f:
        return f.read()

def get_all_nist_cve_urls(oldest) -> list:
    urls = [] 
   

    current = datetime.now().year    

    for year in range(oldest, current+1):
        url = f"{NIST_DATA_FEEDS_URL}nvdcve-1.1-{year}.json.gz"
        urls.append(url)

    return urls

def create_nist_merged_cve_json():

    import glob
    import json

    result = []

    # go ahead and download all the MSRC security updates fresh
    for url in get_all_nist_cve_urls(2016):
        print(f"Downloading {url}")
        cve_data_json = json.loads(download_extract_gz(url))

        result.append(cve_data_json)

   
    with gzip.open(NIST_CVE_MERGED_PATH, "w") as f:
        f.write(json.dumps(result).encode("utf-8"))

    print("Created {} with len {}".format(NIST_CVE_MERGED_PATH,len(result)))

@lru_cache(None)
def get_nist_merged_cve_json():
    return get_file_json(NIST_CVE_MERGED_PATH,__file__)

def update():

    print(f"Updating {NIST_CVE_MERGED_PATH}...")
    
    start = time.time()
    # create the merged nist json file    
    create_nist_merged_cve_json()
    elapsed = time.time() - start
    
    count = len(get_nist_merged_cve_json())
    
    update_metadata(NIST_CVE_MERGED_PATH,{'sources': [NIST_DATA_FEEDS_URL]}, count, elapsed)

    print("Loaded {} with length {}".format(NIST_CVE_MERGED_PATH, count))


if __name__ == "__main__":
    update()