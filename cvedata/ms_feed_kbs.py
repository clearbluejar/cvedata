import re
import feedparser
import requests
import calendar
from pathlib import Path
import json
import time
import pandas as pd
import io

from .config import DATA_DIR, CACHE_PATH
from .metadata import update_metadata, should_update
from .util import get_file_json

# https://support.microsoft.com/en-us/rss-feed-picker

WIN10_FEED_URL = "https://support.microsoft.com/en-us/feed/atom/6ae59d69-36fc-8e4d-23dd-631d98bf74a9"
WIN11_FEED_URL = "https://support.microsoft.com/en-us/feed/atom/4ec863cc-2ecd-e187-6cb3-b50c6545db92"
WIN_SERVER_2022_FEED_URL = "https://support.microsoft.com/en-us/feed/atom/2d67e9fb-2bd2-6742-08ee-628da707657f"
WIN_SERVER_2019_FEED_URL = "https://support.microsoft.com/en-us/feed/atom/eb958e25-cff9-2d06-53ca-f656481bb31f"
WIN_SERVER_2016_FEED_URL = "https://support.microsoft.com/en-us/feed/atom/c3a1be8a-50db-47b7-d5eb-259debc3abcc"

# WIN_SERVER_2012_R2_FEED_URL = "https://support.microsoft.com/en-us/feed/atom/3ec8448d-ebc8-8fc0-e0b7-9e8ef6c79918"

FEED_URLS = [WIN10_FEED_URL, WIN11_FEED_URL, WIN_SERVER_2022_FEED_URL, WIN_SERVER_2019_FEED_URL, WIN_SERVER_2016_FEED_URL]

MS_KB_FEED_UPDATES_PATH = Path(DATA_DIR, 'ms-kb-feed-updates.json')
MS_KB_FEED_FILES_UPDATED_PATH = Path(DATA_DIR, 'ms-kb-feed-to-files-updated.json.gz')
MS_KBS_TO_BINS_PATH = Path(DATA_DIR, 'ms-kbs-bins.json.gz')

DOWNLOAD_HTML_PATH = Path(CACHE_PATH, 'ms-kb-html-downloaded.json')
DOWNLOAD_HTML_FILEINFO_PATH_PRE = Path(CACHE_PATH)

broken_urls = []


def create_ms_kb_feeds():

    updates = {}

    if DOWNLOAD_HTML_PATH.exists():
        downloaded_html = json.loads(DOWNLOAD_HTML_PATH.read_text())
    else:
        downloaded_html = {}

    
    for feed_url in FEED_URLS:
        
        try: 
            feed = feedparser.parse(feed_url)
                
            for entry in feed.entries:

                print(entry.title)
                print(entry.published)
                print(entry.updated)
                print(entry.link)

                # winbindex updates_kb inspired regex and parsing

                # modified to match titles in Atom Feed
                p = r"(\w+) (\d+),? (\d+) ?(?:&#x2014;|[-|—]) ?KB ?(\d{7})(?: Update for Windows 10 Mobile)? ? ?\(OS Builds? .+?\)(.*)?"

                # special error case
                if "2021—KB5001339" in entry.title:
                    entry.title += ')'

                if "(OS Build OS 17763.529)" in entry.title:
                    entry.title = entry.title.replace('(OS Build OS 17763.529)', '(OS Build 17763.529)')

                if "Windows Server base OS container image" in entry.title:
                    continue

                kb_info = re.findall(p, entry.title)

                # Ensure we don't miss any
                if "OS Build" in entry.title:
                    assert len(kb_info[0]) == 5

                if len(kb_info) == 1 and len(kb_info[0]) == 5:
                    
                    month, date, year, kb_number, extra = kb_info[0]

                    # parsing from winbindex start
                    month_num = list(calendar.month_name).index(month.capitalize())
                    full_date = f'{year}-{month_num:02}-{int(date):02}'
                    update_kb = 'KB' + kb_number
                    match = re.search(r'\(OS Builds? ([\d\.]+)', entry.title)
                    os_build = match[1]
                    # end

                    
                    
                    # It is possible for KBs to exist across feeds. There data should match, just need to add the feed

                    if updates.get(update_kb):
                        assert updates[update_kb]['link'] == entry.link
                        feeds = updates[update_kb]['feeds'].append(feed.feed.title)
                    else:
                        feeds = [feed.feed.title]
                    
                    extra = extra.strip()


                    if downloaded_html.get(update_kb) and downloaded_html[update_kb]['updated'] == entry.updated:
                        html = downloaded_html[update_kb]['html']
                    else:
                        html = requests.get(entry.link).text
                        assert len(html) > 50                    
                        downloaded_html[update_kb] = {'html': html, 'updated': entry.updated}

                        # Cache result
                        # DOWNLOAD_HTML_PATH.write_text(json.dumps(downloaded_html))

                    
                    p = r'http[s]?:\/\/download\.microsoft\.com\/download\/(.*\.csv)'
                    file_info = re.findall(p,html)

                    assert len(file_info) <= 2

                    file_info_urls = []
                    for info in file_info:
                        if "SSU" in info:
                            continue
                        file_info_url = 'https://download.microsoft.com/download/' + info
                        file_info_urls.append(file_info_url)
                        print(file_info_url)

                    
                    if "os-build-14393-447-e2b054d7-cf9f-fa8d-da91-12a069ea3b6a" in entry.link: 

                        file_info_url = "http://download.microsoft.com/download/f/f/4/ff4c473f-a993-43d8-a73b-cb5d07cf15ed/3200970.csv"
                        file_info_urls.append(file_info_url)
                    elif "kb3201845-os-build-14393-479-a3c591b1-0bf6-9d49-5341-d914bd89c74f" in entry.link:
                        file_info_url = "http://download.microsoft.com/download/7/e/d/7ed0046b-8c41-4c90-8fbf-95c414e65cba/3201845.csv"
                        file_info_urls.append(file_info_url)
                    elif "october-27-2016-kb3197954-os-build-14393-351-5a66cc67-c32c-2ef8-4a00-87b8b5de17e3" in entry.link:
                        file_info_url = "http://download.microsoft.com/download/2/a/b/2ab30d12-c80d-42a0-a8f1-d5ddd77321ec/3197954.csv"
                        file_info_urls.append(file_info_url)
                    # elif "exchange-server-2016-fails-on-windows-server-2016-0de48a12-780a-af87-6d4b-36d0247b5d59" in entry.link:
                    #     file_info_url = "http://download.microsoft.com/download/5/6/6/566ba474-4595-4538-91e3-2dfd10494c4f/3194798.csv"
                    #     file_info_urls.append(file_info_url)
                    elif "2016-kb3194798-os-build-14393-321-4a3e7bbc-fe5f-ed29-3148-afc6c9b42903" in entry.link:
                        file_info_url = "http://download.microsoft.com/download/5/6/6/566ba474-4595-4538-91e3-2dfd10494c4f/3194798.csv"
                        file_info_urls.append(file_info_url)                    
                    elif not "c3b5c8c8f2fd" in html: # handle broken csv link
                        assert len(file_info_urls) == 1



                    update_to_append = {
                        'link': entry.link,
                        'releaseDate': full_date,
                        'releaseVersion': os_build,
                        'title': entry.title,
                        'fileInfoUrl': file_info_url,
                        'published': entry.published,
                        'updated': entry.updated,
                        'extra': extra,
                        'feeds': feeds
                        
                    }

                    updates[update_kb] = update_to_append
        finally:
            DOWNLOAD_HTML_PATH.write_text(json.dumps(downloaded_html))    
    
    MS_KB_FEED_UPDATES_PATH.write_text(json.dumps(updates,indent=4))


def get_data_and_lines_to_skip(csv_path, kb):

    nums = []

    header_row = None
    header_key = r'File name[,|"]'
    lines = None
    kb_release = kb['releaseVersion']

    with open(csv_path) as f:
        csv_data = f.read()

    # some headers contain an extra space 'File  name' instead of 'File name'
    # https://stackoverflow.com/questions/71340271/ single space keep newline

    # return this modified data
    csv_data = re.sub(r"(?:(?!\n)\s)+", " ", csv_data)

    # handle corrupt or insane csv

    missing_header_kbs = ['4041691', '4022723', '4034658', '4019472', '4015217', '4025339', '4013429', '4034661', '4038801', '4022715',
                          '3216755', '4025339', '4013429', '3216755', '4038782', '4025334', '4015438', '4010672', '4052231', '4041688',
                          '4039396']

    print(kb)
    if '4601354' in kb['fileInfoUrl']:
        # Sometime they use the wrong header (ie KB4601354)
        csv_data = csv_data.replace(
            "Name,Version,ModifiedTime,ModifiedTime,Size", "File name,File version,Date,Time,File size")
    elif any(kb_num in kb['fileInfoUrl'] for kb_num in missing_header_kbs):
        # Some files just lack headers altogether (ie KB4041691)
        csv_data = "File name,File version,File size,Date,Time,Platform\n" + csv_data

    total_matching_file_count = csv_data.count(kb_release)

    lines = csv_data.splitlines()

    # find first row
    for i, line in enumerate(lines):

        if re.search(header_key, line) and 'version' in line.lower():
            header_row = i
            break

        # skip data before header
        nums.append(i)

    assert header_row is not None

    # get list of all possible lines matching data
    data_start = header_row+1
    kb_release_match_count = 0
    for i, line in enumerate(lines[data_start:], data_start):

        # every valid line should have a version
        version = re.search(r'"?(\d+\.)+(\d+\.)+(\d+\.)+(\d+)"?', line)

        if not version:
            nums.append(i)
            continue

        # filter out lines that still have version type string
        # File name,X86_6caee0f752de99d643fe60d7f84687a6_b77a5c561934e089_4.0.14917.113_none_bf2d2f85b39b6572.manifest,,,,
        if 'file name' in line.lower():
            # subtract one match from total
            if kb_release in version[0]:
                total_matching_file_count -= 1
            nums.append(i)
            continue

        # only save those that match the updated release
        # this will miss files, but only looking for updated
        if not kb_release in version[0]:

            # capture files
            if kb_release.split('.')[-1] in version[4]:
                continue
            nums.append(i)
            continue

        #print(f"MATCHED: {line}")
        kb_release_match_count += 1

    # print(csv_path)
    assert total_matching_file_count == kb_release_match_count

    return csv_data, nums

def create_ms_kb_feed_files():

    if should_update(MS_KB_FEED_FILES_UPDATED_PATH,1):

        kbs_json = get_ms_kb_feeds_json()

        kb_dfs = []        
        all_kb_csv_dfs = pd.DataFrame()
        count = 0

        for kb in kbs_json:

            csv_url = kbs_json[kb]['fileInfoUrl']
            csv_name = csv_url.split('/')[-1]
            csv_path = Path(DOWNLOAD_HTML_FILEINFO_PATH_PRE,csv_name)

            print(csv_url)

            if not csv_path.exists():
                res = requests.get(csv_url)
                assert res.status_code == 200
                csv_path.write_text(res.text)

            count += 1
            print(f"Downloaded {count} of {len(kbs_json)} : {(count / len(kbs_json)) * 100}%")

        for i,kb in enumerate(kbs_json):

            csv_url = kbs_json[kb]['fileInfoUrl']
            csv_name = csv_url.split('/')[-1]
            csv_path = Path(DOWNLOAD_HTML_FILEINFO_PATH_PRE,csv_name)
            
            csv_data, rows_to_skip = get_data_and_lines_to_skip(csv_path,kbs_json[kb])

            kb_csv_df = pd.read_csv(io.StringIO(csv_data), skiprows=rows_to_skip)

            # lowercase column names to fix csv inconsitencies
            kb_csv_df.columns= kb_csv_df.columns.str.lower()

            # some df don't have platform
            kb_csv_df['platform'] = kb_csv_df.get('platform', default=None)

            # keep only valid columns
            valid_columns = ['file name','file version','file size','date','time','platform']
            kb_csv_df = kb_csv_df[valid_columns]

            # junk_columns = ['SP requirement', 'Service branch']
            # kb_csv_df.drop(columns=junk_columns,errors='ignore',inplace=True)
            
            # attach some relevant data
            kb_csv_df['kb'] = kb
            kb_csv_df['kb release'] = kbs_json[kb]['releaseDate']
            kb_csv_df['kb extra'] = kbs_json[kb]['extra']
            kb_csv_df['kb release version'] = kbs_json[kb]['releaseVersion']
            
            # drop duplicates if same file name and version (only looking to get fact of file in df)
            print(kb_csv_df.head())
            kb_csv_df = kb_csv_df[~kb_csv_df.duplicated(subset=['file name', 'file version'],keep='first')]        
            print(kb_csv_df.head())
            print(kb_csv_df.columns)
            assert len(kb_csv_df.columns) == 10
            kb_dfs.append(kb_csv_df)
            
            print(f"Read {i} of {len(kbs_json)}")


        all_kb_csv_dfs = pd.concat(kb_dfs)
        
        del kb_dfs

        all_kb_csv_dfs.reset_index(drop=True,inplace=True)

        all_kb_csv_dfs.to_json(MS_KB_FEED_FILES_UPDATED_PATH,indent=4)
    else:
        all_kb_csv_dfs = pd.read_json(MS_KB_FEED_FILES_UPDATED_PATH)

    print(all_kb_csv_dfs.head())

def create_ms_kb_to_bins():

    all_kb_csv_dfs = pd.read_json(MS_KB_FEED_FILES_UPDATED_PATH)

    # drop manifest files
    all_kb_csv_dfs = all_kb_csv_dfs[~all_kb_csv_dfs['file name'].str.contains('.manifest')]


    #all_kb_csv_dfs.set_index('kb', inplace=True)
    all_kb_csv_dfs = all_kb_csv_dfs.groupby(by=['kb']).aggregate(set)

    

    all_kb_csv_dfs['updated'] = all_kb_csv_dfs['file name'].apply(lambda x: sorted(list(x)))
    all_kb_csv_dfs['build'] = all_kb_csv_dfs['kb release version'].apply(lambda x: list(x)[0])
    all_kb_csv_dfs['release'] = all_kb_csv_dfs['kb release'].apply(lambda x: list(x)[0])
    all_kb_csv_dfs['bin count'] = all_kb_csv_dfs['updated'].apply(lambda x: len(x))
    
    cols = ['updated','build','release','bin count' ]
    print(all_kb_csv_dfs.columns)
    print(all_kb_csv_dfs[cols].head())

    all_kb_csv_dfs[cols].to_json(MS_KBS_TO_BINS_PATH)    

def get_ms_kb_feeds_json():
    return get_file_json(MS_KB_FEED_UPDATES_PATH,__file__)

def get_ms_kb_feed_files_json():
    return get_file_json(MS_KB_FEED_FILES_UPDATED_PATH,__file__)

def get_ms_kb_to_bins_json():
    return get_file_json(MS_KB_FEED_UPDATES_PATH,__file__)    

def update():

    print(f"Updating {MS_KB_FEED_UPDATES_PATH}...")
    
    start = time.time()   
    create_ms_kb_feeds()
    elapsed = time.time() - start

    count = len(get_ms_kb_feeds_json())

    update_metadata(MS_KB_FEED_UPDATES_PATH,{'sources': FEED_URLS}, count, elapsed, swap_axes=True)


    print(f"Updating {MS_KB_FEED_FILES_UPDATED_PATH}...")
    
    start = time.time()   
    create_ms_kb_feed_files()
    elapsed = time.time() - start

    count = len(get_ms_kb_feed_files_json())

    update_metadata(MS_KB_FEED_FILES_UPDATED_PATH,{'sources': FEED_URLS}, count, elapsed, swap_axes=False)

    print(f"Updating {MS_KBS_TO_BINS_PATH}...")
    
    start = time.time()   
    create_ms_kb_to_bins()
    elapsed = time.time() - start

    count = len(get_ms_kb_to_bins_json())

    update_metadata(MS_KBS_TO_BINS_PATH,{'sources': FEED_URLS}, count, elapsed, swap_axes=False)
    

if __name__ == "__main__":
    update()