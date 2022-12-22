from datetime import datetime
import json
import gzip
import requests
import os
import time
import glob
from pathlib import Path
from functools import lru_cache

from .config import DATA_DIR, CACHE_PATH
from .metadata import update_metadata, should_update
from .util import get_file_json

MSRC_CVRF_MERGED_PATH = Path(DATA_DIR, 'msrc-cvrf-merged.json.gz')
MSRC_API_URL = "https://api.msrc.microsoft.com/"
MSRC_CVRF_CACHE_PATH = Path(CACHE_PATH, 'msrc_cvrfs')
MSRC_CVRF_CACHE_PATH.mkdir(exist_ok=True,parents=True)

def get_all_knowledge_base_cvrf():
    cvrfs = []    
    url = "{}cvrf/v2.0/updates".format(MSRC_API_URL)
    headers = {}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = json.loads(response.content)

        for cvrf in data['value']:
            if len(cvrf['ID']) > 0:                
                if "Early" in cvrf['DocumentTitle']:
                    print(f"Skipping early update {cvrf['DocumentTitle']}")
                    continue
                get_knowledge_base_cvrf_json(cvrf)

    return

def get_knowledge_base_cvrf_json(cvrf):

    cvrf_id = cvrf['ID']
    force_download = False

    if cvrf_id is None:
        return None

    month =  time.strptime(cvrf_id.split('-')[1],'%b').tm_mon
    year = int(cvrf_id.split('-')[0])
    
    # MSRC CVRF is not available before Apr 2016
    if year < 2016 or year == 2016 and month < 4:
        return None

    cvrf_json = None

    # if file exists locally, load it    
    cvrf_file = Path(MSRC_CVRF_CACHE_PATH, cvrf_id + ".json")

    if cvrf_file.exists():         
        last_update = datetime.strptime(cvrf['CurrentReleaseDate'],"%Y-%m-%dT%H:%M:%SZ")
        try:
            last_updated = datetime.strptime(json.loads(cvrf_file.read_text())['DocumentTracking']['CurrentReleaseDate'],"%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            # handle odd case missing Z in time format string
            last_updated = datetime.strptime(json.loads(cvrf_file.read_text())['DocumentTracking']['CurrentReleaseDate'],"%Y-%m-%dT%H:%M:%S")
        if last_updated < last_update:
            print(f"{cvrf_file.name} out of date. Last updated: {last_updated} Current version: {last_update}")
            force_download = True        

    if not os.path.exists(cvrf_file) or force_download:
        url = "{}cvrf/v2.0/cvrf/{}".format(
            MSRC_API_URL, cvrf_id)
        headers = {'Accept': 'application/json'}
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            # try once more
            response = requests.get(url, headers=headers)

        if response.status_code != 200:
            # skip if it's this month
            now = datetime.now()
            if year == now.year and month == now.month:            
                return None
            else:
                raise Exception(f'Failed to download MSRC data for {cvrf_id}')

        # cache to disk        
        with open(cvrf_file, 'w') as f:
            json.dump(json.loads(response.content), f)
    else: 
        print(f"Using cached {cvrf_id}")

    assert(os.path.exists(cvrf_file))
    with open(cvrf_file) as f:
        cvrf_json = json.load(f)
    
    return cvrf_json


def create_msrc_merged_cvrf_json():

    result = []

    # go ahead and download all the MSRC security updates fresh
    get_all_knowledge_base_cvrf()

    # Use created file unless outdated
    if should_update(MSRC_CVRF_MERGED_PATH,1):
    
        for f in glob.glob(os.path.join(MSRC_CVRF_CACHE_PATH, "*.json")):
            with open(f, "r") as infile:
                cvrf = json.load(infile)
                if cvrf.get('Vulnerability'):
                    result.append(cvrf)
                else:
                    print(f"skipping {f} lacking Vulnerability info")

        
        with gzip.open(MSRC_CVRF_MERGED_PATH, "w") as f:
            f.write(json.dumps(result).encode("utf-8"))

        print(f"Created {MSRC_CVRF_MERGED_PATH} with len {len(result)}")
    else:
        print(f"{MSRC_CVRF_MERGED_PATH} already exists. Skipping update!")

@lru_cache(None)
def get_msrc_merged_cvrf_json():
    return get_file_json(MSRC_CVRF_MERGED_PATH,__file__)

def get_msrc_merged_cvrf_json_keyed() -> dict:

    def _get_cvrf_id(cvrf):
        return cvrf['DocumentTracking']['Identification']['ID']['Value']


    msrc_merged_json = get_msrc_merged_cvrf_json()

    return {_get_cvrf_id(cvrf): cvrf for cvrf in msrc_merged_json}

def update():
    print(f"Updating {MSRC_CVRF_MERGED_PATH}...")
    
    start = time.time()
    create_msrc_merged_cvrf_json()
    elapsed = time.time() - start

    # open it
    cvrf_json = get_msrc_merged_cvrf_json()

    count = len(cvrf_json)

    update_metadata(MSRC_CVRF_MERGED_PATH,{'sources': [MSRC_API_URL]},count,elapsed)


if __name__ == "__main__":
    update()
