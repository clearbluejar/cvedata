from datetime import datetime
import json
import gzip
import requests
import os

import io
from functools import lru_cache

from .config import DATA_DIR, CACHE_PATH

NIST_CVE_MERGED_PATH = os.path.join(DATA_DIR, 'nist_merged_cve.json.gz')
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

def get_all_nist_cve_urls() -> list:
    urls = [] 
   

    current = datetime.now().year
    oldest = 2002

    for year in range(oldest, current+1):
        url = f"{NIST_DATA_FEEDS_URL}nvdcve-1.1-{year}.json.gz"
        urls.append(url)

    return urls

def create_nist_merged_cve_json():

    import glob
    import json

    result = []

    # go ahead and download all the MSRC security updates fresh
    for url in get_all_nist_cve_urls():

        cve_data_json = json.loads(download_extract_gz(url))

        result.append(cve_data_json)

   
    with gzip.open(NIST_CVE_MERGED_PATH, "w") as f:
        f.write(json.dumps(result).encode("utf-8"))

    print("Created {} with len {}".format(NIST_CVE_MERGED_PATH,len(result)))

@lru_cache(None)
def get_nist_merged_cve_json():

    try:
        with gzip.open(NIST_CVE_MERGED_PATH) as f:
            return json.load(f)
    except FileNotFoundError as e:
        raise Exception("Missing {}. Please run {}".format(
            NIST_CVE_MERGED_PATH, __file__)) from e


def main():

    # create the merged nist json file    
    create_nist_merged_cve_json()

    # open it
    nist_json = get_nist_merged_cve_json()

    print("Loaded {} with length {}".format(
        NIST_CVE_MERGED_PATH, len(nist_json)))


if __name__ == "__main__":
    main()