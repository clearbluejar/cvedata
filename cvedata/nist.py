from datetime import datetime
import json
import gzip
import requests
import time
from pathlib import Path

import io
from functools import lru_cache

from .config import DATA_DIR
from .metadata import update_metadata
from .util import get_file_json

NIST_CVE_JSON_PREFIX_PATH = Path(DATA_DIR,'nist')
NIST_CVE_JSON_PREFIX_PATH.mkdir(exist_ok=True,parents=True)
NIST_DATA_FEEDS_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/"

NIST_OLDEST_YEAR = 2002

def download_extract_gz(url):
    """
    Read json file from winbindex
    """
    response = requests.get(url)
    
    # if this fails the data would be incomplete
    assert(response.status_code == 200)

    with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as f:
        return f.read()

def get_nist_filename_by_year(year):
    return f"nvdcve-1.1-{year}.json.gz"

def get_nist_url_by_year(year):
    return f"{NIST_DATA_FEEDS_URL}{get_nist_filename_by_year(year)}"

def get_all_nist_cve_urls(oldest) -> list:
    urls = [] 
   

    current = datetime.now().year    

    for year in range(oldest, current+1):
        url = get_nist_url_by_year(year)
        urls.append([year,url])

    return urls

# decided to save them individually due to size
def create_nist_year_cve_jsons():

    all_nist_cves = {}
    nist_cves = {}

    # Download NIST CVEs and index them
    for year,url in get_all_nist_cve_urls(NIST_OLDEST_YEAR):

        start = time.time()
        
        nist_year_path = Path(NIST_CVE_JSON_PREFIX_PATH, get_nist_filename_by_year(year))

        if nist_year_path.exists():
            print(f"Already created {nist_year_path}, skipping!")
            with gzip.GzipFile(nist_year_path) as f:
                nist_cves = json.load(f)
        else:
            print(f"Downloading {url}")
            data = download_extract_gz(url)

            nist_cves = json.loads(data)

            cves = {}

            # index by cve id
            for cve in nist_cves['CVE_Items']:
                cve_id = cve['cve']['CVE_data_meta']['ID']
                cves[cve_id] = cve
    
            # delete non indexed copy of cves
            nist_cves.pop('CVE_Items')

            nist_cves['cves'] = cves

            with gzip.GzipFile(nist_year_path,'w') as f:
                f.write(json.dumps(nist_cves).encode("utf-8"))

        count = len(nist_cves['cves'])
        elapsed = time.time() - start

        update_metadata(nist_year_path,{'sources': [NIST_DATA_FEEDS_URL]}, count, elapsed,normalize=True,key_data='cves')

        print(f"Created {nist_year_path} with CVE count {count}")

        # this really speeds up processing time
        del nist_cves
    

# cache this so its fast
@lru_cache(None)
def get_nist_cve_json_by_year(year):
    print(f"Loading {get_nist_filename_by_year(year)}")  
    return get_file_json(Path(NIST_CVE_JSON_PREFIX_PATH,get_nist_filename_by_year(year)),__file__)

def get_cve(cve: str):
    
    try:
        year = cve.split('-')[1]
    except IndexError:
        return None
    
    nist_cves_json = get_nist_cve_json_by_year(year)

    return nist_cves_json['cves'].get(cve)

def get_cves(cves: list): 

    cve_results = []

    for cve in cves:
        if cve:
            cve_results.append(get_cve(cve))

    return cve_results

def update():
    create_nist_year_cve_jsons()

if __name__ == "__main__":
    update()
   