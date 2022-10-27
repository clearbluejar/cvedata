from datetime import datetime
import json
import gzip
import requests
import os
import time
from pathlib import Path
from functools import lru_cache

from .config import DATA_DIR, CACHE_PATH
from .metadata import update_metadata
from .util import get_file_json

MSRC_CVRF_MERGED_PATH = Path(DATA_DIR, 'msrc_cvrf_merged.json.gz')
MSRC_API_URL = "https://api.msrc.microsoft.com/"

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
                get_knowledge_base_cvrf_json(cvrf['ID'])

    return

def get_knowledge_base_cvrf_json(cvrf_id):
    if cvrf_id == None:
        return None

    from time import strptime
    month =  strptime(cvrf_id.split('-')[1],'%b').tm_mon
    year = int(cvrf_id.split('-')[0])
    
    # MSRC CVRF is not available before Apr 2016
    if year < 2016 or year == 2016 and month < 4:
        return None

    cvrf_json = None

    if not os.path.exists(CACHE_PATH):
        os.makedirs(CACHE_PATH,exist_ok=True)

    # if file exists locally, load it
    cvrf_file = Path(CACHE_PATH, cvrf_id + ".json")

    if not os.path.exists(cvrf_file):        
        url = "{}cvrf/v2.0/cvrf/{}".format(
            MSRC_API_URL, cvrf_id)
        headers = {'Accept': 'application/json'}
        response = requests.get(url, headers=headers)
        # if this fails the data would be incomplete
        assert(response.status_code == 200)
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

    import glob


    result = []

    # go ahead and download all the MSRC security updates fresh
    get_all_knowledge_base_cvrf()

    # Use created file unless outdated
    # if os.path.exists(path):
    #     current_year = datetime.now().year
    #     current_month = datetime.now().month
    #     mod_time = datetime.fromtimestamp(os.path.getmtime(path))
    #     if mod_time.month == current_month and mod_time.year == current_year:
    #         print("{} already up to date.".format(path))
    #         return
        
    for f in glob.glob(os.path.join(CACHE_PATH, "*.json")):
        with open(f, "r") as infile:
            cvrf = json.load(infile)
            if cvrf.get('Vulnerability'):
                result.append(cvrf)
            else:
                print(f"skipping cvrf {cvrf['DocumentTitle']} lacking Vulnerability info")

    
    with gzip.open(MSRC_CVRF_MERGED_PATH, "w") as f:
        f.write(json.dumps(result).encode("utf-8"))

    print("Created {} with len {}".format(MSRC_CVRF_MERGED_PATH,len(result)))

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
