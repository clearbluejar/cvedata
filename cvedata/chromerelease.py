from bs4 import BeautifulSoup
import requests
from datetime import datetime
import json
import os
import time
from pathlib import Path

from .config import DATA_DIR
from .metadata import update_metadata
from .util import get_file_json

CHROME_RELEASE_URL = "https://chromereleases.googleblog.com"
RAW_SCRAPE_CHROME_JSON_PATH = Path(DATA_DIR, 'chromerelease-raw-cve.json')
PARSED_CHROME_JSON_PATH = Path(DATA_DIR, 'chromerelease-cve.json')


def scrape_chromerelease_cves():

    urls = []
    raw_cves = []

    # Build list of chromerelease blog urls
    current_year = datetime.now().year
    current_month = datetime.now().month

    # Use created file unless outdated
    if os.path.exists(RAW_SCRAPE_CHROME_JSON_PATH):
        mod_time = datetime.fromtimestamp(
            os.path.getmtime(RAW_SCRAPE_CHROME_JSON_PATH))
        if mod_time.month == current_month and mod_time.year == current_year:
            with open(RAW_SCRAPE_CHROME_JSON_PATH) as f:
                raw_cves = json.load(f)
                return raw_cves

    for year in range(2008, current_year+1):
        for month in range(1, 12+1):

            # updates start in september 2008
            if year == 2008 and month < 9:
                continue

            # updates end at current month and year
            if year == current_year and month > current_month:
                continue

            urls.append("{}/{}/{:02d}".format(CHROME_RELEASE_URL, year, month))

    # Scrape the CVEs (sorry)
    for url in urls:
        print(url)

        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, "html.parser")

            month_cve_count = 0

            # href simple heuristic
            # - https://crbug.com/915975
            # - http://code.google.com/p/chromium/issues/detail?id=72517
            for a in soup.find("body").findAll("a"):

                bug_id = None
                found_cve = None

                # all (most) CVEs have bug id link
                if "crbug" in a.attrs['href'] or "code.google.com" in a.attrs['href']:

                    if len(a.attrs['href'].split('/')) == 4 and a.attrs['href'].split('/')[3].isnumeric():
                        bug_id = a.attrs['href'].split('/')[3]
                    elif len(a.attrs['href'].split('id=')) == 2 and a.attrs['href'].split('id=')[1].isnumeric():
                        bug_id = a.attrs['href'].split('id=')[1]

                    # make sure CVE is in text
                    if "CVE" in a.parent.text and bug_id:

                        # parent contains multiple CVEs
                        if len(a.parent.text) > 300:

                            if "Reported by" in a.parent.text:
                                # carve out specific one
                                bug_id_base = a.parent.text.find(bug_id)
                                start = a.parent.text.rfind(
                                    '[$', 0, bug_id_base)
                                # $reward should appear pretty close.. likely this is a invalid one
                                # if (bug_id_base - start) > 20:
                                #     print('bad case')
                                # continue
                                end = a.parent.text.find('[$', bug_id_base)
                                # handle error cases
                                if end == -1:

                                    # dumb heuristic to cleanup final thank you in report
                                    if a.parent.text.find('We would', bug_id_base) != -1:
                                        end = a.parent.text.find(
                                            'We would', bug_id_base)
                                    elif a.parent.text.find('[', bug_id_base) != -1:
                                        end = a.parent.text.find(
                                            '[', bug_id_base)
                                    elif a.parent.text.find('Reported', bug_id_base) == -1:
                                        continue  # If can't find reported by after then likely doesn't have info

                                # print(a.parent.text[start:end].strip())
                                if a.parent.text[start:end].strip().count('Reported by') > 2:
                                    raise 'asdf'
                                found_cve = [url.split(
                                    '/')[-2]+'-'+url.split('/')[-1], a.attrs['href'], a.parent.text[start:end].strip()]
                        else:
                            found_cve = [url.split(
                                '/')[-2]+'-'+url.split('/')[-1], a.attrs['href'], a.parent.text.strip()]

                        if found_cve:
                            raw_cves.append(found_cve)
                            month_cve_count += 1

            print("Found {} CVEs for {}".format(month_cve_count, url))
            print("Total {} CVEs".format(len(raw_cves)))
        else:
            print("Failed to get url {}".format(url))

    with open(RAW_SCRAPE_CHROME_JSON_PATH, 'w') as f:
        json.dump(raw_cves, f)

    return raw_cves


def parse_chrome_release_list(raw_cves):

    # Sample strings
    # [$1000] [111779] High CVE-2011-3021: Use-after-free in subframe loading. Credit to Arthur Gerkis.
    # [$10,500][725032] High CVE-2017-5087: Sandbox Escape in IndexedDB. Reported by Ned Williamson on 2017-05-22

    cves = []
    import re

    count = 0

    for raw_cve in raw_cves:

        cve = {}

        # try:
        cve['blog_id'] = raw_cve[0]
        cve['url'] = raw_cve[1]

        reward = re.search(r'\[\$(\d+|TBD|N/A|n/a)\]', raw_cve[2])
        bug_id = re.search(r'\[(\d+)\]', raw_cve[2])
        severity = re.search(r'(Critical|High|Low|Medium)', raw_cve[2])
        cve_id = re.search(r'CVE-\d+-\d+', raw_cve[2])
        description = re.search(r'CVE-\d+-\d+(: *)(.*)\. ', raw_cve[2])
        date = re.search(r'\d\d\d\d-\d\d-\d\d', raw_cve[2])
        twitter = re.search(r'^.*?\btwitter\.com/@?(\w{1,15})(?:[?/,\"].*)?$',raw_cve[2])

        if not twitter:
            twitter = re.search(r'(?<![\w.-])@([A-Za-z][\w-]+)',raw_cve[2])

     
        cve['twitter'] = twitter[1] if twitter else twitter


        cve['reward'] = reward[1] if reward else reward
        cve['bug_id'] = bug_id[1] if bug_id else bug_id
        cve['severity'] = severity[0].strip() if severity else severity
        cve['cve_id'] = cve_id[0] if cve_id else cve_id

        # cve['description'] = description[1].strip(':').split(
        #    '.')[0].strip() if description else description

        cve['description'] = description[2].strip(':').split(
            '.')[0].strip() if description else description

        # set date
        if date:
            cve['date'] = date[0]
        else:
            cve['date'] = raw_cve[0]+'-01'

        # set ack
        if "Reported by" in raw_cve[2]:
            cve['acknowledgment'] = raw_cve[2].split('Reported by')[1].split(' on ')[
                0]
        elif "Credit to" in raw_cve[2]:
            cve['acknowledgment'] = raw_cve[2].split(
                'Credit to')[1]
        else:
            cve['acknowledgment'] = None

        if cve['acknowledgment']:
            cve['acknowledgment'] = cve['acknowledgment'].strip().strip(
                '.').lower().replace('\n', '')

        # set twitter handle



        if cve['description']:
            search = re.search(
                r'(.*)( in | with | via | between | when | from | related to | on )(.*)', cve['description'])

            if search:
                cve['type'] = search[1].replace('-', ' ').lower()
                cve['component'] = search[3].replace('-', ' ').lower()
            else:
                print(cve['description'])
                cve['type'] = None
                cve['component'] = None

        else:
            cve['type'] = None
            cve['component'] = None

        cves.append(cve)

    print("Parsed cves with len {} written to {}".format(
        len(cves), PARSED_CHROME_JSON_PATH))

    with open(PARSED_CHROME_JSON_PATH, 'w') as f:
        json.dump(cves, f)


def get_chromerelease_cve_json():
    return get_file_json(PARSED_CHROME_JSON_PATH,__file__)

def update():
    
    print(f"Updating {RAW_SCRAPE_CHROME_JSON_PATH}...")
    start = time.time()
    
    # Scrape Chrome Release acknowledgments
    raw_cves = scrape_chromerelease_cves()
    elapsed = time.time() - start

    count = len(json.loads(RAW_SCRAPE_CHROME_JSON_PATH.read_text()))

    update_metadata(RAW_SCRAPE_CHROME_JSON_PATH,{'sources': [CHROME_RELEASE_URL]},count,elapsed,swap_axes=False)

    # Parse
    print(f"Updating {PARSED_CHROME_JSON_PATH}...")
    start = time.time()
    parse_chrome_release_list(raw_cves)
    elapsed = time.time() - start

    count = len(get_chromerelease_cve_json())
    
    update_metadata(PARSED_CHROME_JSON_PATH,{'sources': [CHROME_RELEASE_URL]},count,elapsed,'cve_id',normalize=True)


if __name__ == "__main__":
    update()
