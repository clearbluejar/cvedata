import json
import time
import difflib
import re
from pathlib import Path
from functools import lru_cache
import pandas as pd
import itertools

from .config import DATA_DIR
from .msrc_cvrf import MSRC_API_URL
from .metadata import update_metadata, should_update
from .winbindex import get_winbindex_desc_to_bin_map, get_winbindex_kbs_to_bin_map, WINBINDEX_GITHUB_URL
from .win_verinfo import get_verinfo_desc_to_bins_json
from .msrc_pandas import get_msrc_tags, get_msrc_titles, get_msrc_cvrf_pandas_json
from .msrc_known_bins import KNOWN_TAG_TO_BIN_MAP, KNOWN_TITLE_TO_BIN_MAP
from .ms_feed_kbs import get_ms_kb_to_bins_json,FEED_URLS
from .util import get_file_json

MSRC_CVE_ALL_BINS_PATH = Path(DATA_DIR,"msrc-cve-all-bins-list.json")

MSRC_TAG_FILE_NAMES_PATH = Path(DATA_DIR,"msrc-cve-tags-combined-file-names.json")
MSRC_TITLE_FILE_NAMES_PATH = Path(DATA_DIR,"msrc-cve-titles-combined-file-names.json")

MSRC_CVE_ALL_DESC_TO_BINS_PATH = Path(DATA_DIR,"msrc-cve-combined-desc-to_bins.json")
MSRC_TAGS_TO_DESC_SIMS_PATH = Path(DATA_DIR,"msrc-cve-tags-combined-file-desc-sims.json")
MSRC_TITLES_TO_DESC_SIMS_PATH = Path(DATA_DIR,"msrc-cve-titles-combined-file-desc-sims.json")
SIMS = [.25, .45, .5, .55, .75, .9, 1]

MSRC_CVE_KBS_PATH = Path(DATA_DIR,"msrc-cve-combined-kbs.json")
MSRC_CVE_TO_BINS_PATH = Path(DATA_DIR,"msrc-cve-to-bins.json")

MIN_FILE_NAMES_CUTOFF = .75

@lru_cache(None)
def clean_tag(tag):
    if not tag:
        return ''

    tag = tag.lower().strip()

    if tag == ' ' or tag == 'windows' or tag == 'microsoft office':
        return ''

    if len(tag.split()) > 2:
        tag = re.sub('windows|dll|role:|microsoft|and|service|services|explorer|calc|office', '', tag)

    tag = re.sub('[^\. 0-9a-zA-Z]+', '', tag)      

    return tag.strip()

def get_match_at_cutoff(key: str,possibilities: dict,cutoff: float = 0.6) -> list:
    """
    Leverages difflib to produce list of binaries for possibilities at cutoff
    """

    if key is None:
        return []

    key = clean_tag(key)
    matches = difflib.get_close_matches(key,possibilities.keys(),n=10000,cutoff=cutoff)

    # map keys to bins
    bins = [bin for desc in matches for bin in possibilities[desc]]
    return bins

def get_tag_similarity_df(row : str,key : str,desc_to_bins: dict,col_pre : str,min_sims: list):
    """
    Builds similarity columns into Dataframe at min_sims value intervals
    """

    bins = {}

    # init bins
    for min_sim in min_sims:
            bins.setdefault(min_sim,[])

    ctag1 = clean_tag(row[key]).split()

    for desc in desc_to_bins:

        # check for bad/common tag
        if len(ctag1) == 0:
            break
        
        ctag2 = clean_tag(desc).split()

        if len(ctag2) == 0:
            continue
        
        s = difflib.SequenceMatcher(None,ctag1,ctag2)
        
        if s.real_quick_ratio() > min_sims[0] and s.quick_ratio() > min_sims[0]:               
            
            #sim = difflib.SequenceMatcher(None,ctag1,ctag2).ratio()
            sim = s.ratio()

            # add bins to 
            for min_sim in min_sims:                      
                if sim >= min_sim:
                    [bins[min_sim].append(bin) for bin in desc_to_bins[desc]]

    for sim_score in bins:
        row[f"{col_pre}-{sim_score}"] = bins[sim_score]

    return row


def cve_to_bin(row,tags_sim_df: pd.DataFrame,titles_sim_df: pd.DataFrame,kb_feed: dict,tags_bins: dict, titles_bins: dict, verbose=False):
    """
    Magic Algorithm to map a MSRC CVE to a Windows Binary Name
    """

    bins = set()

    cve = row.name
    tag = row['Tag']
    title = row['Title']

    if verbose:
        print(cve)
        print(row['Tag'])
        print(row['Title'])
    
    if tag and tag.lower() in KNOWN_TAG_TO_BIN_MAP:
        for bin in KNOWN_TAG_TO_BIN_MAP[tag.lower()]:
            bins.add(bin)

    if title and title.lower() in KNOWN_TITLE_TO_BIN_MAP:
        for bin in KNOWN_TITLE_TO_BIN_MAP[title.lower()]:
            bins.add(bin)

    if tags_bins.get(tag):
        for bin in tags_bins.get(tag):
            bins.add(bin)

    if titles_bins.get(tag):
        for bin in titles_bins.get(tag):
            bins.add(bin)
    
    if tag and "microsoft" in tag.lower():
        tag_min = 'vi-0.55'
    else:
        tag_min = 'vi-0.45'

    if title and "microsoft" in title.lower():
        title_min = 'vi-0.55'
    else:
        title_min = 'vi-0.45'

    if tags_sim_df[tag_min].get(tag):
        for bin in tags_sim_df[tag_min].loc[tag]:
            bins.add(bin)

    if titles_sim_df[title_min].get(title):
        for bin in titles_sim_df[title_min].get(title):
            bins.add(bin)

    # updated_bins    
    updated_bins = []
    for kb in row['KBs'].split():        
        kb_updated_files = kb_feed.get(kb)
        if kb_updated_files:
            updated_bins.extend(kb_updated_files)

    row['Updated'] = list(set(updated_bins).intersection(bins))
    row['Updated Count'] = len(row['Updated'])
    row['Bins'] = list(bins)
    row['Bins Count'] = len(row['Bins'])

    return row

def get_msrc_cve_filtered_titles() -> list:
    """
    Filter any titles within skip_titles
    """
    titles = get_msrc_titles()

    skip_words = ['Chromium CVE']

    return [title for title in titles if not any(skip in title for skip in skip_words)]

def create_combined_name_desc_files():

    win_verinfo_desc = get_verinfo_desc_to_bins_json()
    wb_descs = get_winbindex_desc_to_bin_map()

    sources = [wb_descs, win_verinfo_desc]

    bin_names = []

    for source in sources:
        for desc in source:
            for bin in source[desc]:
                bin_names.append(bin)

    # unique bin names
    bin_names = list(set(bin_names))

    print(f"Create all bins with len {len(bin_names)}")
    MSRC_CVE_ALL_BINS_PATH.write_text(json.dumps(bin_names))


    all_desc_to_bin = {}

    for source in sources:
        for desc in source:
            all_desc_to_bin.setdefault(desc,[])
            all_desc_to_bin[desc].extend(source[desc])

    # remove space key
    del all_desc_to_bin[' ']

    #unique the bins
    all_desc_to_bin_unique = {}
    for desc in all_desc_to_bin:
        all_desc_to_bin_unique[desc] = list(set(all_desc_to_bin[desc]))

        if len(all_desc_to_bin_unique[desc]) >= 50:
            print(f"desc: {desc} too big?")

    MSRC_CVE_ALL_DESC_TO_BINS_PATH.write_text(json.dumps(all_desc_to_bin_unique))


def create_msrc_cve_file_names():

    all_bin_names = {}
    tags_to_bins = {}
    titles_to_bins = {}

    bin_names = get_msrc_all_bins()

    for bin in bin_names:
        all_bin_names[bin] = [bin]


    # create tag map
    if should_update(MSRC_TAG_FILE_NAMES_PATH,1):
        tags = get_msrc_tags()        

        for tag in tags:
            tags_to_bins[tag] = get_match_at_cutoff(tag,all_bin_names,MIN_FILE_NAMES_CUTOFF)

        MSRC_TAG_FILE_NAMES_PATH.write_text(json.dumps(tags_to_bins))
    else:        
        tags_to_bins = json.loads(MSRC_TAG_FILE_NAMES_PATH.read_text())
        print(f"Loading cached {MSRC_TAG_FILE_NAMES_PATH} with len {len(tags_to_bins)}")


    if should_update(MSRC_TITLE_FILE_NAMES_PATH,1):
        titles = get_msrc_cve_filtered_titles()

        for title in titles:
            titles_to_bins[title] = get_match_at_cutoff(title,all_bin_names,MIN_FILE_NAMES_CUTOFF)

        MSRC_TITLE_FILE_NAMES_PATH.write_text(json.dumps(titles_to_bins))
    else:
        titles_to_bins = json.loads(MSRC_TITLE_FILE_NAMES_PATH.read_text())
        print(f"Loading cached {MSRC_TITLE_FILE_NAMES_PATH} with len {len(titles_to_bins)}")
    

def create_msrc_cves_file_descs():

    all_desc_to_bins = get_msrc_all_desc_to_bins()    

    # desc keys that will never match in get_tag_similarity_df
    clean_desc_to_bins = {}

    for desc,bins in all_desc_to_bins.items():
        if len(clean_tag(desc)) > 0:
            clean_desc_to_bins[desc] = bins

    if should_update(MSRC_TAGS_TO_DESC_SIMS_PATH,1):
    
        tags = get_msrc_tags()

        # matches = difflib.get_close_matches(' '.join([tag for tag in tags if tag]),clean_desc_to_bins,n=1000000,cutoff=.001)
        
        # clean_desc_to_bins = {}
        # for desc in matches:
        #     clean_desc_to_bins[desc] = all_desc_to_bins[desc]

        key = 'Tag'
        tags_sim_df = pd.DataFrame(tags,columns= ['Tag'])
        print(tags_sim_df.head())
        tags_sim_verinfo_df = tags_sim_df.apply(get_tag_similarity_df,args=(key,clean_desc_to_bins,'vi',SIMS),axis=1)
        tags_sim_verinfo_df = tags_sim_verinfo_df.set_index('Tag')
        print(tags_sim_verinfo_df.head(25))
        print(tags_sim_verinfo_df.apply(lambda s: s.map(lambda x: len(x) if x else 0)).mean())
        tags_sim_verinfo_df.to_json(MSRC_TAGS_TO_DESC_SIMS_PATH)
    else:
        tags_sim_verinfo_df = pd.read_json(MSRC_TAGS_TO_DESC_SIMS_PATH)
        print(f"Loaded cached {MSRC_TAGS_TO_DESC_SIMS_PATH} with len {tags_sim_verinfo_df.shape[0]}")

    if should_update(MSRC_TITLES_TO_DESC_SIMS_PATH,1):
        key = 'Title'
        titles_sim_df = pd.DataFrame(get_msrc_cve_filtered_titles(),columns= ['Title'])    
        print(titles_sim_df.head())
        titles_sim_verinfo_df = titles_sim_df.apply(get_tag_similarity_df,args=(key,clean_desc_to_bins,'vi',SIMS),axis=1)
        titles_sim_verinfo_df = titles_sim_verinfo_df.set_index('Title')
        print(titles_sim_verinfo_df.head(25))
        print(titles_sim_verinfo_df.apply(lambda s: s.map(lambda x: len(x) if x else 0)).mean())
        titles_sim_verinfo_df.to_json(MSRC_TITLES_TO_DESC_SIMS_PATH)
    else:
        titles_sim_verinfo_df = pd.read_json(MSRC_TITLES_TO_DESC_SIMS_PATH)
        print(f"Loaded cached {MSRC_TITLES_TO_DESC_SIMS_PATH} with len {titles_sim_verinfo_df.shape[0]}")

def create_msrc_cve_kbs():

    wb_kbs = get_winbindex_kbs_to_bin_map()
    ms_kbs = get_ms_kb_to_bins_json()
    
    # create winbindex df
    wb_kbs_df = pd.DataFrame.from_dict(wb_kbs, orient='index')
    wb_kbs_df['bin count'] = wb_kbs_df['updated'].apply(lambda x: len(x))
    without_bins = wb_kbs_df[wb_kbs_df['bin count'] == 0].index
    wb_kbs_df = wb_kbs_df.drop(without_bins)
    wb_kbs_df.sort_values(by=['bin count'], ascending=False)
    print(wb_kbs_df.head())

    # load ms_feed kb
    ms_kbs_df = pd.DataFrame.from_dict(ms_kbs).sort_values(by=['bin count'], ascending=False)  
    print(ms_kbs_df.head())
    
    # combine both together
    all_kbs_df = pd.concat([wb_kbs_df,ms_kbs_df]).sort_index()
    all_kbs_df.index.name = 'kb'
    all_kbs_df = all_kbs_df.groupby('kb').aggregate(list)
    
    # merge and unique updated bins
    all_kbs_df['updated'] = all_kbs_df['updated'].apply(lambda x: list(set(itertools.chain.from_iterable(x))))

    all_kbs_df['bin count'] = all_kbs_df['updated'].apply(len)

    all_kbs_df.to_json(MSRC_CVE_KBS_PATH)
    print(all_kbs_df.head())

    print(f"Created {MSRC_CVE_KBS_PATH} with len {all_kbs_df.shape[0]}")

def create_msrc_cve_to_bins():

    all_cvrf_df = pd.DataFrame.from_dict(get_msrc_cvrf_pandas_json())
    print(all_cvrf_df.head())

    tags_sims_df = pd.DataFrame.from_dict(get_msrc_tags_to_desc_sims())
    print(tags_sims_df.head())

    titles_sims_df = pd.DataFrame.from_dict(get_msrc_titles_to_desc_sims())
    print(titles_sims_df.head())

    kb_feeds = pd.DataFrame.from_dict(get_msrc_cve_kbs()).to_dict()['updated']

    tags_to_bins = get_msrc_tag_file_names()
    titles_to_bins = get_msrc_title_file_names()

    bins_all_cvrf_df = all_cvrf_df.apply(cve_to_bin,args=(tags_sims_df,titles_sims_df,kb_feeds, tags_to_bins, titles_to_bins),axis=1)

    bins_all_cvrf_df.to_json(MSRC_CVE_TO_BINS_PATH)
    print(bins_all_cvrf_df.head())



def get_msrc_all_desc_to_bins() -> dict:
    return get_file_json(MSRC_CVE_ALL_DESC_TO_BINS_PATH,__file__)


def get_msrc_all_bins() -> dict:
    return get_file_json(MSRC_CVE_ALL_BINS_PATH,__file__)

def get_msrc_tag_file_names() -> dict:
    return get_file_json(MSRC_TAG_FILE_NAMES_PATH,__file__)

def get_msrc_title_file_names() -> dict:
    return get_file_json(MSRC_TITLE_FILE_NAMES_PATH,__file__)

def get_msrc_tags_to_desc_sims() -> dict:
    return get_file_json(MSRC_TAGS_TO_DESC_SIMS_PATH,__file__)

def get_msrc_titles_to_desc_sims() -> dict:
    return get_file_json(MSRC_TITLES_TO_DESC_SIMS_PATH,__file__)        

def get_msrc_cve_kbs() -> dict:
    return get_file_json(MSRC_CVE_KBS_PATH,__file__) 


def get_msrc_cve_to_bins() -> dict:
    return get_file_json(MSRC_CVE_TO_BINS_PATH,__file__)


def check_known_tags():
    """
    Verify Known Tags List user Valid Keys
    """

    tags = [tag.lower() for tag in get_msrc_tags() if tag]


    for tag in KNOWN_TAG_TO_BIN_MAP:
        assert tag in tags

def check_known_titles():
    """
    Verify Known Tags List user Valid Keys
    """

    titles = [title.lower() for title in get_msrc_titles()]

    for title in KNOWN_TITLE_TO_BIN_MAP:
        assert title in titles

def update():

    check_known_tags()
    check_known_titles()

    print(f"Updating {MSRC_CVE_ALL_DESC_TO_BINS_PATH}...")
    print(f"Updating {MSRC_CVE_ALL_BINS_PATH}...")

    start = time.time()
    create_combined_name_desc_files()
    elapsed = time.time() - start
    
    count = len(get_msrc_all_desc_to_bins())
    update_metadata(MSRC_CVE_ALL_DESC_TO_BINS_PATH,{'sources': [WINBINDEX_GITHUB_URL,MSRC_API_URL]}, count, elapsed, normalize=True,swap_axes=True)
    
    count = len(get_msrc_all_bins())
    update_metadata(MSRC_CVE_ALL_BINS_PATH,{'sources': [WINBINDEX_GITHUB_URL,MSRC_API_URL]}, count, elapsed, normalize=True)
    
    
    print(f"Updating {MSRC_TAG_FILE_NAMES_PATH}...")
    print(f"Updating {MSRC_TITLE_FILE_NAMES_PATH}...")
    
    start = time.time()
    create_msrc_cve_file_names()
    elapsed = time.time() - start
    
    count = len(get_msrc_all_bins())
    update_metadata(MSRC_CVE_ALL_BINS_PATH,{'sources': [WINBINDEX_GITHUB_URL,MSRC_API_URL]}, count, elapsed, normalize=True)

    count = len(get_msrc_tag_file_names())
    update_metadata(MSRC_TAG_FILE_NAMES_PATH,{'sources': [WINBINDEX_GITHUB_URL,MSRC_API_URL]}, count, elapsed, swap_axes=True, normalize=True)

    count = len(get_msrc_title_file_names())
    update_metadata(MSRC_TITLE_FILE_NAMES_PATH,{'sources': [WINBINDEX_GITHUB_URL,MSRC_API_URL]}, count, elapsed, swap_axes=True, normalize=True)


    print(f"Updating {MSRC_TAGS_TO_DESC_SIMS_PATH}...")
    print(f"Updating {MSRC_TITLES_TO_DESC_SIMS_PATH}...")
      
    start = time.time()
    create_msrc_cves_file_descs()
    elapsed = time.time() - start

    count = len(get_msrc_tags_to_desc_sims())
    update_metadata(MSRC_TAGS_TO_DESC_SIMS_PATH,{'sources': [WINBINDEX_GITHUB_URL,MSRC_API_URL]}, count, elapsed, swap_axes=False)

    count = len(get_msrc_titles_to_desc_sims())
    update_metadata(MSRC_TITLES_TO_DESC_SIMS_PATH,{'sources': [WINBINDEX_GITHUB_URL,MSRC_API_URL]}, count, elapsed, swap_axes=False)

    print(f"Updating {MSRC_TITLES_TO_DESC_SIMS_PATH}...")
      
    start = time.time()
    create_msrc_cve_kbs()
    elapsed = time.time() - start

    count = len(get_msrc_cve_kbs())
    update_metadata(MSRC_CVE_KBS_PATH,{'sources': [WINBINDEX_GITHUB_URL].extend(FEED_URLS)}, count, elapsed, swap_axes=False)
    

    # print(f"Updating {MSRC_CVE_TO_BINS_PATH}...")
    
    start = time.time()
    create_msrc_cve_to_bins()
    elapsed = time.time() - start
    
    count = len(get_msrc_cve_to_bins())
    update_metadata(MSRC_CVE_TO_BINS_PATH,{'sources': [WINBINDEX_GITHUB_URL,MSRC_API_URL].extend(FEED_URLS)}, count, elapsed, swap_axes=True,normalize=True)


if __name__ == "__main__":
    update()