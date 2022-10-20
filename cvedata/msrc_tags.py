import os
import json
import time
import pathlib
import difflib

from .config import DATA_DIR
from .msrc_cvrf import get_msrc_merged_cvrf_json,MSRC_API_URL
from .metadata import update_metadata
from .winbindex import get_winbindex_desc_to_bin_map, WINBINDEX_GITHUB_URL

MSRC_TAGS_PATH = os.path.join(DATA_DIR,"msrc-tags-merged.json")
MSRC_TAGS_FREQ_PATH = os.path.join(DATA_DIR,"msrc-tags-merged-frequency.json")
MSRC_TAGS_AND_DESC_TO_BINS_PATH = os.path.join(DATA_DIR,"msrc-tags-and-desc-to-bins.json")
MIN_SIMILARITY = 0.41

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
    if "remote procedure" in tag1 and "remote procedure" in tag2:
        print(f"{ctag1}:{ctag2}: {sim}")
    return sim


def create_tags_desc_to_bins():
    tags_json = get_msrc_tags()

    wb_desc_to_bin_json : dict = get_winbindex_desc_to_bin_map()
    # filtered_wb_desc_to_bin_json = {}


    # #filter out any description below threshold
    # for bin_desc in wb_desc_to_bin_json:
    #     keep = False
    #     for tag in tags_json:
    #         if get_tag_similarity(tag,bin_desc) > MIN_SIMILARITY:
    #             keep = True
    #             break
            
    #     if keep:
    #         filtered_wb_desc_to_bin_json[bin_desc] = wb_desc_to_bin_json[bin_desc]


    print(len(tags_json))
    print(len(wb_desc_to_bin_json))

    tags_desc_to_bins = {}

    for tag in tags_json:

        tags_desc_to_bins.setdefault(tag,[])

        for bin_desc in wb_desc_to_bin_json:
            sim = get_tag_similarity(tag,bin_desc)
            if sim > MIN_SIMILARITY:
                #print(f"{sim} - {clean_tag(tag)} - {clean_tag(wb_tag)}")
                [tags_desc_to_bins[tag].append(bin_name) for bin_name in wb_desc_to_bin_json[bin_desc] if bin_name not in tags_desc_to_bins[tag]]

    tags_desc_to_bins = {k: tags_desc_to_bins[k] for k in sorted(tags_desc_to_bins,key=lambda x: x, reverse=True)}

    for tag in tags_desc_to_bins:
        if len(tags_desc_to_bins[tag]) > 10:
            print(tag)

    with open(MSRC_TAGS_AND_DESC_TO_BINS_PATH, 'w') as f:
        json.dump(tags_desc_to_bins,f,indent=4)

def get_tags_desc_to_bins() -> dict:
    try:
        with open(MSRC_TAGS_AND_DESC_TO_BINS_PATH) as f:
            return json.load(f)
    except FileNotFoundError as e:
        raise Exception("Missing {}. Please run {}".format(
            MSRC_TAGS_AND_DESC_TO_BINS_PATH, __file__)) from e

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
    try:
        with open(MSRC_TAGS_PATH) as f:
            return json.load(f)
    except FileNotFoundError as e:
        raise Exception("Missing {}. Please run {}".format(
            MSRC_TAGS_PATH, __file__)) from e

def update():

    print(f"Updating {pathlib.Path(MSRC_TAGS_PATH).name} and {pathlib.Path(MSRC_TAGS_FREQ_PATH).name}...")
    
    start = time.time()   
    create_msrc_tags()
    elapsed = time.time() - start

    count = len(get_msrc_tags())

    update_metadata(MSRC_TAGS_PATH,{'sources': [MSRC_API_URL], 'generation_time': elapsed,  'count': count})

    print(f"Updating {pathlib.Path(MSRC_TAGS_AND_DESC_TO_BINS_PATH).name}...")
    
    start = time.time()
    create_tags_desc_to_bins()
    elapsed = time.time() - start
    
    count = len(get_tags_desc_to_bins())
    update_metadata(MSRC_TAGS_AND_DESC_TO_BINS_PATH,{'sources': [WINBINDEX_GITHUB_URL,MSRC_API_URL], 'generation_time': elapsed, 'count': count})


if __name__ == "__main__":
    update()