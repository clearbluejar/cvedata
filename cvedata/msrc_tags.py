import os
import json
import time
from pathlib import Path
import difflib

from .config import DATA_DIR
from .msrc_cvrf import get_msrc_merged_cvrf_json,MSRC_API_URL
from .metadata import update_metadata
from .winbindex import get_winbindex_desc_to_bin_map, WINBINDEX_GITHUB_URL
from .known_tag_to_bin import KNOWN_TAG_TO_BIN_MAP
from .util import get_file_json

MSRC_TAGS_PATH = Path(DATA_DIR,"msrc-tags-merged.json")
MSRC_TAGS_FREQ_PATH = Path(DATA_DIR,"msrc-tags-merged-frequency.json")
MSRC_TAGS_AND_DESC_TO_BINS_PATH = Path(DATA_DIR,"msrc-tags-to-bins.json")

# controls the relationship of file description to tags
MIN_SIMILARITY = 0.45
MAX_BINS_PER_TAG = 10

def clean_tag(tag):
    import re
    tag = tag.lower()
    if len(tag.split()) > 2:
        tag = re.sub('windows|dll|role:|microsoft|and|service|services|explorer|calc', '', tag)        

    tag = re.sub('[^\. 0-9a-zA-Z]+', '', tag)      

    return tag.strip()

def get_tag_similarity(tag1,tag2):  
    ctag1 = clean_tag(tag1).split()
    ctag2 = clean_tag(tag2).split()
    sim = difflib.SequenceMatcher(None,ctag1,ctag2).ratio()
    if "remote procedure" in ctag1 or "remote procedure" in ctag2:
        print(f"{ctag1}:{ctag2}: {sim}")
    return sim


def create_tags_desc_to_bins():
    tags_json = get_msrc_tags()

    wb_desc_to_bin_json : dict = get_winbindex_desc_to_bin_map()

    tags_desc_to_bins = {}

    for tag in tags_json:

        tags_desc_to_bins.setdefault(tag,set())

        if tag in KNOWN_TAG_TO_BIN_MAP:
            for bin in KNOWN_TAG_TO_BIN_MAP[tag]:
                [tags_desc_to_bins[tag].add(bin_name) for bin_name in KNOWN_TAG_TO_BIN_MAP[tag]]

            # get to next tag
            continue

        # troll through file descriptions attempting to find a match (slow!)
        for bin_desc in wb_desc_to_bin_json:
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

def create_msrc_tags():
    msrc_cvrf_json = get_msrc_merged_cvrf_json()

    tag_set = set()
    tags = []
    

    for cvrf_json in msrc_cvrf_json:
        if cvrf_json.get("Vulnerability"):
            [tag_set.add(note.get('Value').lower()) for vuln in cvrf_json["Vulnerability"] for note in vuln['Notes']
                        if note['Type'] == 7 and note.get('Value')]

            [tags.append(note.get('Value').lower()) for vuln in cvrf_json["Vulnerability"] for note in vuln['Notes']
                        if note['Type'] == 7 and note.get('Value')]

            # [(tags_faqs[note.get('Value').lower()] = 1) for vuln in cvrf_json["Vulnerability"] for note in vuln['Notes']
            #             if note['Type'] == 7 and note.get('Value')]

    # TODO add FAQ to help decode tags
    # tags_faqs = {}
    # for cvrf_json in msrc_cvrf_json:
    #     if cvrf_json.get("Vulnerability"):
    #         for vuln in cvrf_json["Vulnerability"]:   
    #             desc = None
    #             faq = []
    #             tag = None

    #             for note in vuln['Notes']:
    #                 if note.get('Type') == 2:
    #                     assert desc is None
    #                     desc = note.get('Value')
    #                 elif note.get('Type') == 4:
    #                     faq.append(note.get('Value'))
    #                 elif note.get('Type') == 7:
    #                     assert tag is None
    #                     tag = note.get('Value')
    #             tags_faqs.setdefault(tag,[]).append([ desc, faq])

    tag_set = sorted(tag_set)

    print(f"Found {len(tag_set)} tags")

    check_known_tags(tag_set)

    with open(MSRC_TAGS_PATH, 'w') as f:
        json.dump(tag_set,f,indent=4)

    tag_freq = {}
    for tag in tags:
        if tag in tag_freq:
            tag_freq[tag] += 1
        else:
            tag_freq[tag] = 1

    tag_freq = {k: tag_freq[k] for k in sorted(tag_freq,key=lambda x: tag_freq[x], reverse=True)}
    
    with open(MSRC_TAGS_FREQ_PATH, 'w') as f:
        json.dump(tag_freq,f,indent=4)
        

def get_msrc_tags():
    return get_file_json(MSRC_TAGS_PATH, __file__)

def update():

    print(f"Updating {MSRC_TAGS_PATH} and {MSRC_TAGS_FREQ_PATH}...")
    
    start = time.time()   
    create_msrc_tags()
    elapsed = time.time() - start

    count = len(get_msrc_tags())

    update_metadata(MSRC_TAGS_PATH,{'sources': [MSRC_API_URL]}, count, elapsed,normalize=False)

    update_metadata(MSRC_TAGS_FREQ_PATH,{'sources': [MSRC_API_URL]}, count, elapsed,swap_axes=True,normalize=True)

    print(f"Updating {MSRC_TAGS_AND_DESC_TO_BINS_PATH}...")
    
    start = time.time()
    create_tags_desc_to_bins()
    elapsed = time.time() - start
    
    count = len(get_tags_desc_to_bins())
    update_metadata(MSRC_TAGS_AND_DESC_TO_BINS_PATH,{'sources': [WINBINDEX_GITHUB_URL,MSRC_API_URL]}, count, elapsed, swap_axes=True,normalize=True)


if __name__ == "__main__":
    update()