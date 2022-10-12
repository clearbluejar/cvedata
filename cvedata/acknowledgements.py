import json
import os
from itertools import groupby
import re
import time
import pathlib

from .config import DATA_DIR
from .cvrf import get_msrc_merged_cvrf_json, MSRC_API_URL
from .chromerelease import get_chromerelease_cve_json, CHROME_RELEASE_URL
from .metadata import update_metadata

# list of all names available
RESEARCHER_NAMES_JSON_PATH = os.path.join(
    DATA_DIR, 'researcher_names.json')
# list of all names normalized    
RESEARCHER_NAMES_GROUP_JSON_PATH = os.path.join(
    DATA_DIR, 'researcher_names_grouped.json')
# map of all cves to normalized names
RESEARCHER_CVE_MAP_JSON_PATH = os.path.join(
    DATA_DIR, 'researcher_cve_map.json')
# map of all researcher to twitter handle
RESEARCHER_TWITTER_MAP_JSON_PATH = os.path.join(
    DATA_DIR, 'researcher_twitter_map.json')

def create_researcher_names_json():

    names = []

    # Get MSRC CVRF acknowledgements
    msrc_cvrf_json = get_msrc_merged_cvrf_json()

    [names.append(name.get('Value').strip()) for cvrf in msrc_cvrf_json if cvrf.get('Vulnerability') for vuln in cvrf["Vulnerability"]
     for ack in vuln['Acknowledgments'] for name in ack['Name'] if name.get('Value') is not None]

    # Get Chrome acknowledgements
    chrome_release_json = get_chromerelease_cve_json()

    [names.append(cve.get('acknowledgment').strip())
     for cve in chrome_release_json if cve.get('acknowledgment')]

    names = sorted(list(set(names)))

    with open(RESEARCHER_NAMES_JSON_PATH, 'w') as f:
        json.dump(names, f,indent=4)

    print("Found {} researchers written to {}".format(
        len(names), RESEARCHER_NAMES_JSON_PATH))


def cleanup_html_researcher_key(text):
    clean = re.compile('<.*?>|,|Discovered by')
    return re.sub(clean, '', text).strip()


def cleanup_keywords_researcher_key(text):
    clean = re.compile(' of|working with| with| from| and| working|')
    return re.sub(clean, '', text).strip()

# researcher name normalization (using first two keywords)
def create_researcher_names_group_json():

    #names = []
    names = {}
    groups = []

    researcher_json = get_researcher_names_json()

    common_groups = ["trend micro", "microsoft", "qihoo 360", "google chrome", "tencent security",
                     "discovered by", "microsoft corporation", "anonymous", "msrc vulnerabilities", "codesafe team",
                     "microsoft chakra", "", "mark", "twitter", "information", "kunlun lab", "microsoft offensive",
                     "chakra", "trend micro’s"]

    for r in researcher_json:
        # group by first two keyworks (ignoring html)
        key = ' '.join(cleanup_html_researcher_key(r).split(' ')[0:2])
        # remove common keywords to avoid "researcher and" or "researcher from" being different keys
        key = cleanup_keywords_researcher_key(key)
        # cleanup spaces
        key = key.strip()

        # lowercase
        key = key.lower()

        if len(key) <= 3 or key.lower() in common_groups:
            print("Skipping researcher: {} with len {}".format(r, len(r)))
            names.setdefault("ignored researchers", []).append(r)
            continue

        names.setdefault(key, []).append(r)

    # for k, g in groupby(researcher_json, lambda x: cleanup_researcher_key(x).split()[0:2]):
    #     groups.append(list(g))    # Store group iterator as a list
    #     names.append(' '.join(k))

    # with open(RESEARCHER_NAMES_GROUP_JSON_PATH, 'w') as f:
    #     json.dump(groups, f)

    with open(RESEARCHER_NAMES_GROUP_JSON_PATH, 'w') as f:
        json.dump(names, f,indent=4)

    print("Found {} grouped researchers written to {}".format(
        len(names), RESEARCHER_NAMES_GROUP_JSON_PATH))

def create_researcher_cve_map_json():

    researcher_json = get_researcher_names_group_json()

    # get date with reseracher names
    msrc_cvrf_json = get_msrc_merged_cvrf_json()
    chrome_release_json = get_chromerelease_cve_json()

    # GOAT CVEs
    goat_cves = []

    for researcher in researcher_json:
        cves = []

        # MSRC data
        [cves.append(vuln["CVE"]) for cvrf in msrc_cvrf_json if cvrf.get('Vulnerability') for vuln in cvrf["Vulnerability"]
         for ack in vuln['Acknowledgments'] for name in ack['Name'] if name.get('Value') and researcher.lower() in name.get('Value').lower()]

        # chromerelease data
        [cves.append(cve.get('cve_id').strip()) for cve in chrome_release_json if cve.get(
            'cve_id') and cve.get('acknowledgment') and researcher.lower() in cve.get('acknowledgment').lower()]

        # remove duplicates
        cves = set(cves)

        # sort cves
        cves = sorted(cves)        

        goat_cves.append([researcher, cves])

    goat_cves = sorted(goat_cves, key=lambda x: len(x[1]), reverse=True)

    with open(RESEARCHER_CVE_MAP_JSON_PATH, 'w') as f:
        json.dump(goat_cves, f,indent=4)

    print("Found {} grouped researchers written to {}".format(
        len(goat_cves), RESEARCHER_CVE_MAP_JSON_PATH))

# known handles not found in cve parsed data
top_25_hardcoded_researchers = { 
     'yuki chen': 'guhe120',
     'zhiniang peng': 'edwardzpeng',
     'mateusz jurczyk': 'j00ru',
     'james forshaw': 'tiraniddo',
     'xuefeng li': 'lxf02942370',
     'david erceg': 'david_erceg',
     'khalil zhani': 'Khalil_Zhani',
     'lokihardt': 'lokihardt',
     'kdot': None,
     'qixun zhao': 'S0rryMybad',
     'jun kokatsu': 'shhnjk',
     'guang gong': 'oldfresher',
     'miaubiz': 'miaubiz',
     'ashar javed': 'soaj1664ashar',
     'fangming gu': 'afang5472',
     'k0shl': 'KeyZ3r0',
     'dhanesh kizhakkinan': 'dhanesh_k',
     'steven seeley': 'steventseeley',
     'zhong_sf': 'zhong_sf',
     'yangkang': 'dnpushme',
     'huynh phuoc': 'hph0var',
     'hossein lotfi': 'hosselot',
     'pgboy': 'pgboy',
     'nicolas joly': 'n_joly',
     'abdelhamid naceri': 'KLINIX5',
     'atte kettunen': 'attekett',
}



def check_top_x(max) -> int:
    goat = get_researcher_cve_map_json()
    twitter = get_researcher_twitter_map_json()

    found = 0
    for index,r in enumerate(goat):
        if index > max:
            break
        print(f" '{r[0]}' : '{twitter[r[0]][0]}',")
        if twitter[r[0]][0]:
            found += 1            

    print(f"Found {found} twitter handles of {max} of the top researchers")

    return found


def create_researcher_twitter_map_json():
    import re

    researcher_json = get_researcher_names_group_json()
    chrome_release_json = get_chromerelease_cve_json()

    chrome_name_to_twitter_map = {}
    for cve in chrome_release_json:
        if cve.get('acknowledgment') and cve['twitter']:
            chrome_name_to_twitter_map.setdefault(cve['acknowledgment'],set()).add(cve['twitter'])

    #convert set
    for key in chrome_name_to_twitter_map.keys():
        chrome_name_to_twitter_map[key] = str(chrome_name_to_twitter_map[key])

    handle_map = {}

    found_count = 0
    chrome_found = 0
    hardcoded_count = 0
    for researcher in researcher_json:
        
        match = None

        # check chrome list first
        if chrome_name_to_twitter_map.get(researcher):
            match = chrome_name_to_twitter_map[researcher]
            chrome_found += 1
        else:    
            for line in researcher_json[researcher]:                
                match = re.search(r'^.*?\btwitter\.com/@?(\w{1,15})(?:[?/,\"].*)?$',line)
                
                if not match: 
                    match = re.search(r'(?<![\w.-])@([A-Za-z][\w-]+)',line)
                
                if match:
                    found_count += 1                    
                    match = match.group(1)
                    break        

        # last chance
        if not match and top_25_hardcoded_researchers.get(researcher):
            match = top_25_hardcoded_researchers[researcher]
            hardcoded_count += 1

        handle_map.setdefault(researcher,[]).append(match)

    with open(RESEARCHER_TWITTER_MAP_JSON_PATH, 'w') as f:
        json.dump(handle_map, f,indent=4)

    print(f"Found {chrome_found} chrome twitter matches")
    print(f"Found {found_count} group researcher twitter matches")
    print(f"Found {hardcoded_count} hardcoded twitter matches")

    total = chrome_found + found_count + hardcoded_count
    print(f"Found {total} researchers with twitter handles out of {len(researcher_json)} written to {RESEARCHER_TWITTER_MAP_JSON_PATH}")

def get_researcher_names_json():

    try:
        with open(RESEARCHER_NAMES_JSON_PATH) as f:
            return json.load(f)
    except FileNotFoundError as e:
        raise Exception("Missing {}. Please run {}".format(
            RESEARCHER_NAMES_JSON_PATH, __file__)) from e

def get_researcher_names_group_json():

    try:
        with open(RESEARCHER_NAMES_GROUP_JSON_PATH) as f:
            return json.load(f)
    except FileNotFoundError as e:
        raise Exception("Missing {}. Please run {}".format(
            RESEARCHER_NAMES_GROUP_JSON_PATH, __file__)) from e

def get_researcher_cve_map_json():
    try:
        with open(RESEARCHER_CVE_MAP_JSON_PATH) as f:
            return json.load(f)
    except FileNotFoundError as e:
        raise Exception("Missing {}. Please run {}".format(
            RESEARCHER_CVE_MAP_JSON_PATH, __file__)) from e

def get_researcher_twitter_map_json():
    try:
        with open(RESEARCHER_TWITTER_MAP_JSON_PATH) as f:
            return json.load(f)
    except FileNotFoundError as e:
        raise Exception("Missing {}. Please run {}".format(
            RESEARCHER_TWITTER_MAP_JSON_PATH, __file__)) from e


def update():
    
    print(f"Updating {pathlib.Path(RESEARCHER_NAMES_JSON_PATH).name}...")
    
    start = time.time()
    create_researcher_names_json()
    elapsed = time.time() - start
    count = len(get_researcher_names_json())
    update_metadata(RESEARCHER_NAMES_JSON_PATH,{'sources': [CHROME_RELEASE_URL,MSRC_API_URL], 'generation_time': elapsed, 'count': count})

    print(f"Updating {pathlib.Path(RESEARCHER_NAMES_GROUP_JSON_PATH).name}...")
    
    start = time.time()
    create_researcher_names_group_json()
    elapsed = time.time() - start
    count = len(get_researcher_names_group_json())
    update_metadata(RESEARCHER_NAMES_GROUP_JSON_PATH,{'sources': [CHROME_RELEASE_URL,MSRC_API_URL], 'generation_time': elapsed, 'count': count})

    print(f"Updating {pathlib.Path(RESEARCHER_TWITTER_MAP_JSON_PATH).name}...")
    
    start = time.time()
    create_researcher_twitter_map_json()
    elapsed = time.time() - start
    count = len(get_researcher_twitter_map_json())  
    update_metadata(RESEARCHER_TWITTER_MAP_JSON_PATH,{'sources': [CHROME_RELEASE_URL,MSRC_API_URL], 'generation_time': elapsed, 'count': count})
    
    print(f"Updating {pathlib.Path(RESEARCHER_CVE_MAP_JSON_PATH).name}...")
    
    start = time.time()
    create_researcher_cve_map_json()
    elapsed = time.time() - start
    count = len(get_researcher_cve_map_json())    
    update_metadata(RESEARCHER_CVE_MAP_JSON_PATH,{'sources': [CHROME_RELEASE_URL,MSRC_API_URL], 'generation_time': elapsed, 'count': count})


    check_top_x(100)


if __name__ == "__main__":
    update()