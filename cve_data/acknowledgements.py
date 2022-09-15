import json
import os
from itertools import groupby
import re

from .config import DATA_DIR
from .cvrf import get_msrc_merged_cvrf_json
from .chromerelease import get_chromerelease_cve_json
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
                     "microsoft chakra", "", "mark", "twitter"]

    for r in researcher_json:
        # group by first two keyworks (ignoring html)
        key = ' '.join(cleanup_html_researcher_key(r).split(' ')[0:2])
        # remove common keywords to avoid "researcher and" or "researcher from" being different keys
        key = cleanup_keywords_researcher_key(key)
        # cleanup spaces
        key = key.strip()

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


def create_researcher_cve_goat_json():

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
         for ack in vuln['Acknowledgments'] for name in ack['Name'] if name.get('Value') and researcher in name.get('Value')]

        # chromerelease data
        [cves.append(cve.get('cve_id').strip()) for cve in chrome_release_json if cve.get(
            'cve_id') and cve.get('acknowledgment') and researcher in cve.get('acknowledgment')]

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

    # GOAT CVEs grouped

    for i, r in enumerate(goat_cves):

        

        print("{} : {}".format(r[0], len(r[1])))
        if i > 100:
            break

    # goat_cves = []
    # for researcher in researcher_json:

    # GOAT MSRC

    # GOAT Chrome Release


def build_acknowledgements():
    create_researcher_names_json()

    create_researcher_names_group_json()

    create_researcher_cve_goat_json()

    update_metadata()



if __name__ == "__main__":
    build_acknowledgements()