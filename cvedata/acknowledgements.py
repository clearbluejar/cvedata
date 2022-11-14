import json
import os
from itertools import groupby
import pathlib
import re
import time
from pathlib import Path
import pandas as pd

from .config import DATA_DIR, CACHE_PATH
from .msrc_cvrf import get_msrc_merged_cvrf_json, MSRC_API_URL
from .chromerelease import get_chromerelease_cve_json, CHROME_RELEASE_URL
from .metadata import update_metadata, should_update
from .known_ack_to_twitter import KNOWN_ACK_TWITTER_HANDLES
from .nist import get_cves
from .util import get_file_json

# list of all names available
RESEARCHER_NAMES_JSON_PATH = Path(DATA_DIR, 'researcher_names.json')
# list of all names normalized
RESEARCHER_NAMES_GROUP_JSON_PATH = Path(
    DATA_DIR, 'researcher_names_grouped.json')
# map of all cves to normalized names
RESEARCHER_CVE_MAP_JSON_PATH = Path(DATA_DIR, 'researcher_cve_map.json')

# map of all cve scores to normalized names
RESEARCHER_CVE_QUALITY_MAP_JSON_PATH_FULL = Path(CACHE_PATH, 'researcher_cve_quality_map_full.json.gz')
RESEARCHER_CVE_QUALITY_MAP_JSON_PATH = Path(DATA_DIR, 'researcher_cve_quality_map.json')

# map of all researcher to twitter handle
RESEARCHER_TWITTER_MAP_JSON_PATH = Path(
    DATA_DIR, 'researcher_twitter_map.json')


def create_researcher_names_json():

    names = []

    # Get MSRC CVRF acknowledgements
    msrc_cvrf_json = get_msrc_merged_cvrf_json()
    
    [names.append([name.get('Value').strip(), vuln["CVE"]]) for cvrf in msrc_cvrf_json if cvrf.get('Vulnerability') for vuln in cvrf["Vulnerability"]
     for ack in vuln['Acknowledgments'] for name in ack['Name'] if name.get('Value') is not None]

    # Get Chrome acknowledgements
    chrome_release_json = get_chromerelease_cve_json()

    [names.append([cve.get('acknowledgment').strip(),cve.get('cve_id')] )
     for cve in chrome_release_json if cve.get('acknowledgment')]

    # # remove double spaces
    # clean_names = []
    # for name in names:
    #     clean_names.append(re.sub(r"(?:(?!\n)\s)+", " ", name))
    
    # names = sorted(list(set(clean_names)))

    names = sorted(names,key=lambda x: x[0])

    with open(RESEARCHER_NAMES_JSON_PATH, 'w') as f:
        json.dump(names, f, indent=4)

    print("Found {} researchers written to {}".format(
        len(names), RESEARCHER_NAMES_JSON_PATH))


def cleanup_html_researcher_key(text):
    clean = re.compile('()<.*?>|,|Discovered by')
    return re.sub(clean, '', text).strip()


def cleanup_keywords_researcher_key(text):
    clean = re.compile(' of|working with| with| from| and| working|')
    return re.sub(clean, '', text).strip()

# researcher name normalization (using first two keywords)
def create_researcher_names_group_json():

    names = {}
    cves = {}

    researcher_json = get_researcher_names_json()

    common_groups = ["trend micro", "microsoft", "qihoo 360", "google chrome", "tencent security",
                     "discovered by", "microsoft corporation", "anonymous", "msrc vulnerabilities", "codesafe team",
                     "microsoft chakra", "", "mark", "twitter", "information", "kunlun lab", "microsoft offensive",
                     "chakra", "trend micro’s", "crowdstrike", "microsoft office", "microsoft security", "fortinet's fortiguard",
                     "kaspersky lab", "the chromium",]

    

    for item in researcher_json:

        line = item[0]
        cve = item[1]
        # group by first two keyworks (ignoring html)
        key = ' '.join(cleanup_html_researcher_key(line).split()[0:2])
        # remove common keywords to avoid "researcher and" or "researcher from" being different keys
        key = cleanup_keywords_researcher_key(key)
        # cleanup spaces
        key = key.strip()

        # lowercase
        key = key.lower()

        if len(key) <= 3 or key.lower() in common_groups:
            print("Skipping researcher: {} with len {}".format(line, len(line)))
            names.setdefault("ignored researchers", []).append(line)
            continue

        names.setdefault(key, []).append(line)
        cves.setdefault(key, []).append(cve)

    # for k, g in groupby(researcher_json, lambda x: cleanup_researcher_key(x).split()[0:2]):
    #     groups.append(list(g))    # Store group iterator as a list
    #     names.append(' '.join(k))

    # with open(RESEARCHER_NAMES_GROUP_JSON_PATH, 'w') as f:
    #     json.dump(groups, f)

    with open(RESEARCHER_NAMES_GROUP_JSON_PATH, 'w') as f:
        json.dump(names, f, indent=4)

    print("Found {} grouped researchers written to {}".format(
        len(names), RESEARCHER_NAMES_GROUP_JSON_PATH))

    cves = {k : cves[k] for k in sorted(cves, key=lambda x: len(cves[x]), reverse=True)}

    with open(RESEARCHER_CVE_MAP_JSON_PATH, 'w') as f:
        json.dump(cves, f, indent=4)

    print("Found {} grouped researchers written to {}".format(
        len(names), RESEARCHER_CVE_MAP_JSON_PATH))


def create_researcher_cve_quality_map_json():
    
    if should_update(RESEARCHER_CVE_QUALITY_MAP_JSON_PATH_FULL, 1):

        researcher_cves = get_researcher_cve_map_json()

        # GOAT CVEs
        goat_quality = []

        cve_columns = ['publishedDate', 'cve.CVE_data_meta.ID',
        'cve.CVE_data_meta.ASSIGNER', 'cve.problemtype.problemtype_data',
        'cve.description.description_data', 'impact.baseMetricV3.cvssV3.version',
        'impact.baseMetricV3.cvssV3.vectorString',
        'impact.baseMetricV3.cvssV3.attackVector',
        'impact.baseMetricV3.cvssV3.attackComplexity',
        'impact.baseMetricV3.cvssV3.privilegesRequired',
        'impact.baseMetricV3.cvssV3.userInteraction',
        'impact.baseMetricV3.cvssV3.scope',
        'impact.baseMetricV3.cvssV3.confidentialityImpact',
        'impact.baseMetricV3.cvssV3.integrityImpact',
        'impact.baseMetricV3.cvssV3.availabilityImpact',
        'impact.baseMetricV3.cvssV3.baseScore',
        'impact.baseMetricV3.cvssV3.baseSeverity',
        'impact.baseMetricV3.exploitabilityScore',
        'impact.baseMetricV3.impactScore']

        for researcher,cves in researcher_cves:

            cve_data = get_cves(cves)
            cve_df = pd.json_normalize(cve_data)        
            #print(cve_df.columns)
            cve_df = pd.DataFrame(cve_df,columns=cve_columns)
            cve_df['researcher'] = researcher
            #cve_df.set_index('researcher',inplace=True)
            print(cve_df.head())
            #print(cve_data)

            goat_quality.append(cve_df)

        

        goat_quality_df = pd.concat(goat_quality)
        goat_quality_df.reset_index(drop=True,inplace=True)

        goat_quality_df.to_json(RESEARCHER_CVE_QUALITY_MAP_JSON_PATH_FULL)
    else:
        print(f"Loading cached {RESEARCHER_CVE_QUALITY_MAP_JSON_PATH_FULL}.")
        goat_quality_df = pd.read_json(RESEARCHER_CVE_QUALITY_MAP_JSON_PATH_FULL)

    print(goat_quality_df.head())
    quality_cols = ['researcher','impact.baseMetricV3.cvssV3.baseScore', 'impact.baseMetricV3.exploitabilityScore','impact.baseMetricV3.impactScore']
    goat_quality_df = goat_quality_df[quality_cols].groupby(by=['researcher']).mean()
    print(goat_quality_df.sort_values(by=['impact.baseMetricV3.cvssV3.baseScore'],ascending=False))

    goat_quality_df.to_json(RESEARCHER_CVE_QUALITY_MAP_JSON_PATH)

    #print(f"Found {len(goat_quality)} grouped researchers written to {RESEARCHER_CVE_QUALITY_MAP_JSON_PATH}")
    # else:
    #     print(f"Loading cached {RESEARCHER_CVE_MAP_JSON_PATH}.")

def check_top_x(max) -> int:
    goat = get_researcher_cve_map_json()
    twitter = get_researcher_twitter_map_json()

    found = 0
    for index, r in enumerate(goat):
        if index == max:
            break
        print(f" '{r}' : '{twitter[r][0]}',")
        if twitter[r][0] != 'None':
            found += 1

    print(f"Found {found} twitter handles for the top {max} researchers")

    return found


def create_researcher_twitter_map_json():
    import re

    researcher_json = get_researcher_names_group_json()
    chrome_release_json = get_chromerelease_cve_json()

    chrome_name_to_twitter_map = {}
    for cve in chrome_release_json:
        if cve.get('acknowledgment') and cve['twitter']:
            chrome_name_to_twitter_map[cve['acknowledgment']] = cve['twitter']

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
                match = re.search(
                    r'^.*?\btwitter\.com/@?(\w{1,15})(?:[?/,\"].*)?$', line)

                if not match:
                    match = re.search(r'(?<![\w.-])@([A-Za-z][\w-]+)', line)

                if match:
                    found_count += 1
                    match = match.group(1)
                    break

        # last chance
        if not match and KNOWN_ACK_TWITTER_HANDLES.get(researcher):
            match = KNOWN_ACK_TWITTER_HANDLES[researcher]
            hardcoded_count += 1

        handle_map.setdefault(researcher, []).append(match)

    handle_map = {k: handle_map[k] for k in sorted(
        handle_map, key=lambda x: x, reverse=True)}

    with open(RESEARCHER_TWITTER_MAP_JSON_PATH, 'w') as f:
        json.dump(handle_map, f, indent=4)

    print(f"Found {chrome_found} chrome twitter matches")
    print(f"Found {found_count} group researcher twitter matches")
    print(f"Found {hardcoded_count} hardcoded twitter matches")

    total = chrome_found + found_count + hardcoded_count
    print(f"Found {total} researchers with twitter handles out of {len(researcher_json)} written to {RESEARCHER_TWITTER_MAP_JSON_PATH}")


def get_researcher_names_json():
    return get_file_json(RESEARCHER_NAMES_JSON_PATH, __file__)


def get_researcher_names_group_json():
    return get_file_json(RESEARCHER_NAMES_GROUP_JSON_PATH, __file__)


def get_researcher_cve_map_json():
    return get_file_json(RESEARCHER_CVE_MAP_JSON_PATH, __file__)

def get_researcher_cve_quality_map_json():
    return get_file_json(RESEARCHER_CVE_QUALITY_MAP_JSON_PATH, __file__)

def get_researcher_twitter_map_json():
    return get_file_json(RESEARCHER_TWITTER_MAP_JSON_PATH, __file__)


def update():

    print(f"Updating {RESEARCHER_NAMES_JSON_PATH}...")

    start = time.time()
    create_researcher_names_json()
    elapsed = time.time() - start
    count = len(get_researcher_names_json())
    update_metadata(RESEARCHER_NAMES_JSON_PATH, {'sources': [CHROME_RELEASE_URL, MSRC_API_URL]},count,elapsed,normalize=False)    

    print(f"Updating {RESEARCHER_NAMES_GROUP_JSON_PATH}...")
    print(f"Updating {RESEARCHER_CVE_MAP_JSON_PATH}...")

    start = time.time()
    create_researcher_names_group_json()
    elapsed = time.time() - start
    count = len(get_researcher_names_group_json())
    update_metadata(RESEARCHER_NAMES_GROUP_JSON_PATH, {'sources': [CHROME_RELEASE_URL, MSRC_API_URL]},count,elapsed,swap_axes=True,normalize=True)
    update_metadata(RESEARCHER_CVE_MAP_JSON_PATH, {'sources': [CHROME_RELEASE_URL, MSRC_API_URL]},count,elapsed,swap_axes=True,normalize=True)

    print(f"Updating {RESEARCHER_TWITTER_MAP_JSON_PATH}...")

    start = time.time()
    create_researcher_twitter_map_json()
    elapsed = time.time() - start
    count = len(get_researcher_twitter_map_json())
    update_metadata(RESEARCHER_TWITTER_MAP_JSON_PATH, {'sources': [CHROME_RELEASE_URL, MSRC_API_URL]},count,elapsed,swap_axes=True)

    print(f"Updating {RESEARCHER_CVE_QUALITY_MAP_JSON_PATH}...")
    start = time.time()
    create_researcher_cve_quality_map_json()
    elapsed = time.time() - start
    count = len(get_researcher_cve_quality_map_json())
    update_metadata(RESEARCHER_CVE_QUALITY_MAP_JSON_PATH, {'sources': [CHROME_RELEASE_URL, MSRC_API_URL]},count,elapsed,normalize=False)


    check_top_x(100)


if __name__ == "__main__":
    update()
