from curses.ascii import isdigit
import os
import json
import time
import pandas as pd
from datetime import datetime
from pathlib import Path
import difflib


from .config import CACHE_PATH, DATA_DIR, PANDAS_DIR
from .msrc_cvrf import get_msrc_merged_cvrf_json,get_msrc_merged_cvrf_json_keyed,MSRC_API_URL
from .metadata import should_update, update_metadata
# from .msrc_tags import get_tags_desc_to_bins
from .util import get_file_json

MSRC_CVRF_PANDAS = Path(DATA_DIR,"msrc-cvrf-pandas-merged.json.gz")
MSRC_CVRF_PANDAS_FULL = Path(DATA_DIR,"msrc-cvrf-pandas-merged-full.json.gz")
# MSRC_CVE_TAGS_PANDAS = Path(DATA_DIR,"msrc-cve-tag-pandas.json")
MSRC_CVE_TAGS_TITLE = Path(DATA_DIR,"msrc-cve-tag-title.json")

MSRC_TAGS_PATH = Path(DATA_DIR,"msrc-tags-merged.json")
MSRC_TAGS_FREQ_PATH = Path(DATA_DIR,"msrc-tags-merged-frequency.json")
MSRC_TITLES_PATH = Path(DATA_DIR,"msrc-titles-merged.json")
MSRC_TITLES_FREQ_PATH = Path(DATA_DIR,"msrc-titles-merged-frequency.json")

ALL_KBS_VERSION_MAP = Path(CACHE_PATH,"all-msrc-kb-ver-pandas.json") # temporary cache file
MSRC_KB_VERSION = Path(DATA_DIR,"msrc-kb-ver.json")


# MSRC column parsers
def get_tag(notes):
    """
    The MSRC tag points to the affected software component
    """

    tag = None

    for note in notes:

        if note['Type'] == 7:
            # expect there to only be 1 tag
            assert tag is None 
            tag = note['Value']

    return tag

def get_faqs(notes):
    """
    MSRC FAQ provides information related to the CVE context
    """

    faqs = []
    
    for note in notes:
        if note['Type'] == 4:
            faqs.append(note['Value'])            

    return faqs

# def get_kb(rem):
#     """
#     MSRC List of KBs related to CVE
#     """

#     #TODO add URLS
#     #TODO add version numbers

#     kb = None

#     if isinstance(rem,dict):
    
#         if rem['Description'].get('Value'):
#             kb_num = rem['Description']['Value']
#             if str(kb_num).isdigit():
#                 # if rem.get('URL'):
#                 #     kb = f"[KB{kb}]({rem['URL']})"
#                 kb = f"KB{kb_num}"

#     return kb


def get_kbs(rems):
    """
    MSRC List of KBs related to CVE
    """

    #TODO add URLS
    #TODO add version numbers

    kbs = set()
    
    for rem in rems:
        if rem['Description'].get('Value'):
            kb = rem['Description']['Value']
            if str(kb).isdigit():
                # if rem.get('URL'):
                #     kb = f"[KB{kb}]({rem['URL']})"
                kbs.add(f"KB{kb}")
            else:
                print(f"Error: KB non numeric {rem}")

    return ' '.join(sorted(list(kbs)))

def get_version(rem):
    """
    MSRC List of KBs related to CVE
    """

    version = None

    if isinstance(rem,dict):
        # FixedBuild isn't always there
        tmp_version = rem.get('FixedBuild')
        if tmp_version:
            if "http" not in tmp_version:
                version = tmp_version

    return version


def get_kb_and_version(rem):

    row = pd.Series([None,None])

    if isinstance(rem,dict):
        ver = get_version(rem)
        kb =  get_kb(rem)

        

        if ver and kb:
            row = pd.Series([kb,ver])


    return row

def get_versions(rems):
    """
    MSRC List of KBs related to CVE
    """

    versions = set()
    
    for rem in rems:
        # FixedBuild isn't always there
        version = rem.get('FixedBuild')
        if version:
            if "http" not in version:
                versions.add(version)
            else:
                print(f"Error: Fixedbuild non standard error {rem}")

    return ' '.join(sorted(list(versions)))

def get_types(threats):
    """
    MSRC List of KBs related to CVE
    """

    types = set()
    
    for threat in threats:
        if threat.get('Type') == 0:
            if threat.get('Description'):
                types.add(threat['Description']['Value'])       

    if len(types) == 0:
        print(threats)

    return ' '.join(sorted(list(types)))


def get_bins(row):
   
    bins = []

    td_to_bin_map = get_tags_desc_to_bins()

    # TODO user version and KBs to sharpen bins list

    if row['Tag']:
        tag = row['Tag'].lower()

        if td_to_bin_map.get(tag):
            for bin in td_to_bin_map[tag]:
                bins.append(bin)


    return ' '.join(bins)

def get_acks(acks):
    """
    MSRC List of researchers for CVE
    """

    researchers = []
    
    
    for ack in acks:
        if ack.get('Name'):
            for name in ack['Name']:
                if name.get('Value'):
                    researchers.append(name['Value'])

        assert len(ack.get('URL')) == 1

    return ' '.join(sorted(list(researchers)))
    
def get_cvss_base(scores):
    """
    MSRC CVSS Highest Score
    """

    base_scores = []
    
    
    for base in scores:
        if base.get('BaseScore'):
            base_scores.append(base['BaseScore'])

    return max(base_scores, key=lambda x: float(x),default=0)


# Tag utility functions

# def clean_tag(tag):
#     if not tag:
#         return ''
#     import re
#     tag = tag.lower()
#     # if len(tag.split()) > 2:
#     #     tag = re.sub('windows|dll|role:|microsoft|and|service|services|explorer|calc', '', tag)        

#     tag = re.sub('[^\. 0-9a-zA-Z]+', '', tag)      

#     return tag.strip()

def clean_impact(tag):
    if not tag or not isinstance(tag,str):
        return ''
    import re
    #tag = tag.lower()
    if len(tag.split()) > 2:
        tag = re.sub('remote code execution|information disclosure|elevation of privilege|tampering|spoofing|denial of service|security feature bypass|vulnerability|memory corruption', '', tag,flags=re.I)        

    tag = re.sub('[^\. 0-9a-zA-Z]+', '', tag)

    return tag.strip()

# def get_tag_similarity(tag1,tag2):  
#     ctag1 = clean_tag(tag1).split()
#     ctag2 = clean_tag(tag2).split()
#     sim = difflib.SequenceMatcher(None,ctag1,ctag2).ratio()
#     # if "remote procedure" in ctag1 or "remote procedure" in ctag2:
#     #     print(f"{ctag1}:{ctag2}: {sim}")
#     return sim

# def get_sim(x):
#     sims = []
#     tag = x.name
#     for title in x['Title']:
#         sims.append(get_tag_similarity(tag,title))
#     return sims

def create_msrc_cvrf_pandas():

    FIELDS = ["Initial Release", "Title", "Tag", "Impact", "CVSS", "KBs", "Versions", "Acks"]

    if should_update(MSRC_CVRF_PANDAS_FULL,1):
    #if True:

        msrc_merged_json = get_msrc_merged_cvrf_json_keyed()

        cvrf_dfs = []
        
        for cvrf_id in msrc_merged_json:
            
            print(f"Processing {cvrf_id}")
            
            df_update = pd.json_normalize(msrc_merged_json[cvrf_id])
            df_vulns = pd.json_normalize(msrc_merged_json[cvrf_id]['Vulnerability'])
            print(df_vulns.columns)
            

            df_vulns['Tag'] = df_vulns["Notes"].apply(get_tag)
            df_vulns['FAQs'] = df_vulns["Notes"].apply(get_faqs)
            df_vulns['KBs'] = df_vulns["Remediations"].apply(get_kbs)
            df_vulns['Versions'] = df_vulns["Remediations"].apply(get_versions)
            df_vulns['Impact'] = df_vulns['Threats'].apply(get_types)
            df_vulns['CVRF ID'] = df_update['DocumentTracking.Identification.ID.Value'].values[0]    
            df_vulns['Initial Release'] = datetime.strftime(datetime.fromisoformat(df_update['DocumentTracking.InitialReleaseDate'].values[0].replace('Z','')),'%Y-%m-%d')
            df_vulns['Current Release'] = datetime.strftime(datetime.fromisoformat(df_update['DocumentTracking.CurrentReleaseDate'].values[0].replace('Z','')),'%Y-%m-%d')
            df_vulns['Acks'] = df_vulns['Acknowledgments'].apply(get_acks)
            df_vulns['CVSS'] = df_vulns['CVSSScoreSets'].apply(get_cvss_base)
            #df_vulns['Bins'] = df_vulns[['Tag','KBs','Versions']].apply(get_bins,axis=1)
            df_vulns['Title'] = df_vulns['Title.Value'].apply(clean_impact)
            
            df_vulns.set_index('CVE',inplace=True,verify_integrity=True)
            print(df_vulns[FIELDS].head())

            panda_md_path = PANDAS_DIR / f"{cvrf_id}-pandas.md"
            with panda_md_path.open('w') as f:
                f.write(f"# {cvrf_id}\n\n")
                df_vulns[FIELDS].to_markdown(f,tablefmt="github")

            df_vulns[FIELDS].to_json(PANDAS_DIR / f"{cvrf_id}-pandas.json" )

            print(df_vulns[FIELDS].head())

            cvrf_dfs.append(df_vulns)

        all_cvrf_df = pd.concat(cvrf_dfs)
    else:
        all_cvrf_df = pd.read_json(MSRC_CVRF_PANDAS_FULL)

    all_cvrf_df[FIELDS].to_json(MSRC_CVRF_PANDAS)
    all_cvrf_df.to_json(MSRC_CVRF_PANDAS_FULL)

def create_msrc_tags_titles():
    
    all_cvrf_df = pd.read_json(MSRC_CVRF_PANDAS)

    # tag to title
    tags_df = all_cvrf_df[['Tag','Title']]
    tags_title_df = tags_df.reset_index().groupby(['Tag','Title']).aggregate(set)
    tags_title_df.to_json(Path(DATA_DIR,'test.json'))
    print(tags_title_df.head())
    copy_tags_df = tags_df.copy()
    tags_df['Tag Instance Count'] = tags_df['Tag'].apply(lambda x: len(copy_tags_df[copy_tags_df['Tag'] == x]))

    tags_df = tags_df.groupby('Tag').aggregate(set)
    
    tags_df['Title'] = tags_df['Title'].aggregate(list)
    tags_df['Tag Instance Count'] = tags_df['Tag Instance Count'].apply(lambda x: list(x)[0])
    tags_df['Title Length'] = tags_df['Title'].apply(lambda x: len(x))
    #tags_df.index.name = 'Tag'
    tags_df.to_json(MSRC_CVE_TAGS_TITLE,indent=4)

def create_kb_ver():

    # msrc_kb_to_version    
    kb_vers_df = pd.DataFrame()

    if should_update(ALL_KBS_VERSION_MAP,1):
        all_cvrf_df = pd.read_json(MSRC_CVRF_PANDAS_FULL)
        rems = pd.Series(all_cvrf_df['Remediations'].explode('Remediations')) # .dropna().reset_index(drop=True)
        kb_vers_df[['KB','Version']] = rems.apply(get_kb_and_version).dropna()
        kb_vers_df.to_json(ALL_KBS_VERSION_MAP)
    else:
        kb_vers_df = pd.read_json(ALL_KBS_VERSION_MAP)

    kb_vers_df.dropna(axis=1,inplace=True)
    kb_vers_df['Build'] = kb_vers_df['Version'].apply(lambda x: x.split('.')[-2] if (len(x.split('.')) == 4) else None)    
    kb_vers_df = kb_vers_df.groupby('KB').aggregate(set)
    
    # convert columns to list
    kb_vers_df['Version'] = kb_vers_df['Version'].apply(list)
    kb_vers_df['Build'] = kb_vers_df['Build'].apply(list)
    kb_vers_df.to_json(MSRC_KB_VERSION)

def create_msrc_tags():

    all_cvrf_df = pd.read_json(MSRC_CVRF_PANDAS)

    tags_df = all_cvrf_df['Tag'].drop_duplicates()
    
    print(tags_df.head())
    tags_df.to_json(MSRC_TAGS_PATH,indent=4,orient='records')

    freq_df = all_cvrf_df['Tag'].value_counts(ascending=False)
    print(freq_df.head())
    freq_df.to_json(MSRC_TAGS_FREQ_PATH,indent=4)

def create_msrc_titles():

    all_cvrf_df = pd.read_json(MSRC_CVRF_PANDAS)

    titles_df = all_cvrf_df['Title'].drop_duplicates()
    
    print(titles_df.head())
    titles_df.to_json(MSRC_TITLES_PATH,indent=4,orient='records')

    freq_df = all_cvrf_df['Title'].value_counts(ascending=False)
    print(freq_df.head())
    freq_df.to_json(MSRC_TITLES_FREQ_PATH,indent=4)
    
def get_msrc_tags():
    return get_file_json(MSRC_TAGS_PATH, __file__)

def get_msrc_tags_freq():
    return get_file_json(MSRC_TAGS_FREQ_PATH, __file__)
    
def get_msrc_titles():
    return get_file_json(MSRC_TITLES_PATH, __file__)

def get_msrc_titles_freq():
    return get_file_json(MSRC_TITLES_FREQ_PATH, __file__)    

def get_msrc_cvrf_pandas_json():
    return get_file_json(MSRC_CVRF_PANDAS,__file__)

def get_msrc_cvrf_pandas_df():
    return get_file_json(MSRC_CVRF_PANDAS,__file__)

def get_msrc_tags_titles_json():
    return get_file_json(MSRC_CVE_TAGS_TITLE,__file__)
    
def get_kb_ver_json():
    return get_file_json(MSRC_KB_VERSION,__file__)

def update():

    print(f"Updating {MSRC_CVRF_PANDAS}...")
    
    start = time.time()   
    create_msrc_cvrf_pandas()
    elapsed = time.time() - start

    count = len(get_msrc_cvrf_pandas_json())

    update_metadata(MSRC_CVRF_PANDAS,{'sources': [MSRC_API_URL]}, count, elapsed, normalize=False)
    

    print(f"Updating {MSRC_CVE_TAGS_TITLE}...")
    
    start = time.time()   
    create_msrc_tags_titles()
    elapsed = time.time() - start

    count = len(get_msrc_tags_titles_json())

    update_metadata(MSRC_CVE_TAGS_TITLE,{'sources': [MSRC_API_URL]}, count, elapsed, normalize=False,swap_axes=False)

    print(f"Updating {MSRC_KB_VERSION}...")
    
    start = time.time()   
    create_kb_ver()
    elapsed = time.time() - start

    count = len(get_kb_ver_json())

    update_metadata(MSRC_KB_VERSION,{'sources': [MSRC_API_URL]}, count, elapsed, normalize=False)

    print(f"Updating {MSRC_TAGS_PATH} and {MSRC_TAGS_FREQ_PATH}...")
    
    start = time.time()   
    create_msrc_tags()
    elapsed = time.time() - start

    count = len(get_msrc_tags())

    update_metadata(MSRC_TAGS_PATH,{'sources': [MSRC_API_URL]}, count, elapsed,normalize=False)

    update_metadata(MSRC_TAGS_FREQ_PATH,{'sources': [MSRC_API_URL]}, count, elapsed,swap_axes=True,normalize=True)

    start = time.time()   
    create_msrc_titles()
    elapsed = time.time() - start

    count = len(get_msrc_tags())

    update_metadata(MSRC_TITLES_PATH,{'sources': [MSRC_API_URL]}, count, elapsed,normalize=False)

    update_metadata(MSRC_TITLES_FREQ_PATH,{'sources': [MSRC_API_URL]}, count, elapsed,swap_axes=True,normalize=True)


if __name__ == "__main__":
    update()