import json
import time
from pathlib import Path
import difflib
import re

from .config import DATA_DIR
from .msrc_cvrf import MSRC_API_URL
from .metadata import update_metadata
from .winbindex import get_winbindex_desc_to_bin_map, WINBINDEX_GITHUB_URL
from .win_verinfo import get_verinfo_desc_to_bins_json
from .msrc_pandas import get_msrc_tags, get_msrc_titles
from .msrc_known_bins import KNOWN_TAG_TO_BIN_MAP
from .util import get_file_json

MSRC_TAGS_AND_DESC_TO_BINS_PATH = Path(DATA_DIR,"msrc-cve-to-bins.json")

# controls the relationship of file description to tags
MIN_SIMILARITY = 0.55
MAX_BINS_PER_TAG = 10

def get_tag_similarity(tag1,tag2):  
    ctag1 = clean_tag(tag1).split()
    ctag2 = clean_tag(tag2).split()
    sim = difflib.SequenceMatcher(None,ctag1,ctag2).ratio()
    # if "remote procedure" in ctag1 or "remote procedure" in ctag2:
    #     print(f"{ctag1}:{ctag2}: {sim}")
    return sim

def clean_tag(tag):
    if not tag:
        return ''

    tag = tag.lower()
    if len(tag.split()) > 2:
        tag = re.sub('windows|dll|role:|microsoft|and|service|services|explorer|calc|', '', tag)        

    tag = re.sub('[^\. 0-9a-zA-Z]+', '', tag)      

    return tag.strip()
    
def get_tag_similarity_df(row,key,desc_to_bins,col_pre,min_sims):
    """
    Builds similarity columns into Dataframe at min_sims intervals
    """

    bins = {}

    ctag1 = clean_tag(row[key]).split()

    for desc in desc_to_bins:
        
        ctag2 = clean_tag(desc).split()
        sim = difflib.SequenceMatcher(None,ctag1,ctag2).ratio()

        # add bins to 
        for min_sim in min_sims:
            bins.setdefault(min_sim,[])            
            if sim >= min_sim:
                [bins[min_sim].append(bin) for bin in desc_to_bins[desc]]

    bin_results = []

    for sim_score in bins:
        row[f"{col_pre}-{sim_score}"] = bins[sim_score]

    return row

def create_tags_desc_to_bins():
    tags_json = get_msrc_tags()

    titles_json = get_msrc_titles()

    wb_desc_to_bin_json = get_winbindex_desc_to_bin_map()

    verinfo_desc_to_bin_json =  get_verinfo_desc_to_bins_json()

    tags_desc_to_bins = {}

    for tag in tags_json:

        tags_desc_to_bins.setdefault(tag,set())

        if tag in KNOWN_TITLE_TO_BIN_MAP:
            for bin in KNOWN_TAG_TO_BIN_MAP[tag]:
                [tags_desc_to_bins[tag].add(bin_name) for bin_name in KNOWN_TAG_TO_BIN_MAP[tag]]

            # get to next tag
            continue

        # troll through file descriptions attempting to find a match (slow!)
        for bin_desc in wb_desc_to_bin_json:

            if tag in bin_desc:
                [tags_desc_to_bins[tag].add(bin_name) for bin_name in wb_desc_to_bin_json[bin_desc]]
                continue

            sim = get_tag_similarity(tag,bin_desc)            
                
            if sim > MIN_SIMILARITY:
                print(f"{sim} - {clean_tag(tag)} - {clean_tag(bin_desc)}")
                [tags_desc_to_bins[tag].add(bin_name) for bin_name in wb_desc_to_bin_json[bin_desc]]

    tags_desc_to_bins = {k: list(tags_desc_to_bins[k]) for k in sorted(tags_desc_to_bins,key=lambda x: x, reverse=True)}

    # if more than MAX_BINS was found it is suspicious. rank by similarity and drop some    
    for tag in tags_desc_to_bins:
        if len(tags_desc_to_bins[tag]) > MAX_BINS_PER_TAG:            
            tags_desc_to_bins[tag].append('Warning: Tag has more matches than likely')

    with open(MSRC_TAGS_AND_DESC_TO_BINS_PATH, 'w') as f:
        json.dump(tags_desc_to_bins,f,indent=4)

def get_tags_desc_to_bins() -> dict:
    return get_file_json(MSRC_TAGS_AND_DESC_TO_BINS_PATH,__file__)

def  check_known_tags(tag_set):
    """
    Verify Known Tags List user Valid Keys
    """

    for tag in KNOWN_TAG_TO_BIN_MAP:
        assert tag in tag_set

def update():

    print(f"Updating {MSRC_TAGS_AND_DESC_TO_BINS_PATH}...")
    
    start = time.time()
    create_tags_desc_to_bins()
    elapsed = time.time() - start
    
    count = len(get_tags_desc_to_bins())
    update_metadata(MSRC_TAGS_AND_DESC_TO_BINS_PATH,{'sources': [WINBINDEX_GITHUB_URL,MSRC_API_URL]}, count, elapsed, swap_axes=True,normalize=True)


if __name__ == "__main__":
    update()