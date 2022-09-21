import os
import re
import gzip
import json
import difflib

from .config import DATA_DIR
from .win_bin_map import get_win_desc_to_bin_map
from .msrc_tags import get_msrc_tags
from .metadata import update_metadata
from .cvrf import MSRC_API_URL

MSRC_TAGS_TO_BINS_PATH = os.path.join(DATA_DIR,"msrc-tags-to-bins.json")

def clean_tag(tag):
    import re
    tag = tag.lower()
    if len(tag.split()) > 2:
    #if tag != "microsoft windows":
    #     tag = tag.replace("windows",'')
    #     tag = tag.replace("dll",'')
    #     tag = tag.replace("role:",'')
    #     tag = tag.replace("microsoft",'')
    #     tag = tag.replace("and",'')
    #     tag = tag.replace("service",'')
        tag = re.sub('windows|dll|role:|microsoft|and|service|services|explorer', '', tag)        
    

    tag = re.sub('[^\. 0-9a-zA-Z]+', '', tag)        


    return tag.strip()

def get_tag_similarity(tag1,tag2):  
    return difflib.SequenceMatcher(None,clean_tag(tag1).split(),clean_tag(tag2).split()).ratio()

def create_tags_to_bins():
    tags_json = get_msrc_tags()

    wb_tags_json = get_win_desc_to_bin_map()

    print(len(tags_json))
    print(len(wb_tags_json))

    tags_to_bins = {}
    min_similarity = 0.38

    for tag in tags_json:

        tags_to_bins.setdefault(tag,[])

        for wb_tag in wb_tags_json:
            sim = get_tag_similarity(tag,wb_tag)
            if sim > min_similarity:
                #print(f"{sim} - {clean_tag(tag)} - {clean_tag(wb_tag)}")
                [tags_to_bins[tag].append(inner_tag) for inner_tag in wb_tags_json[wb_tag] if inner_tag not in tags_to_bins[tag]]

    tags_to_bins = {k: tags_to_bins[k] for k in sorted(tags_to_bins,key=lambda x: x, reverse=True)}

    with open(MSRC_TAGS_TO_BINS_PATH, 'w') as f:
        json.dump(tags_to_bins,f,indent=4)

def get_tags_to_bins() -> dict:
    try:
        with open(MSRC_TAGS_TO_BINS_PATH) as f:
            return json.load(f)
    except FileNotFoundError as e:
        raise Exception("Missing {}. Please run {}".format(
            MSRC_TAGS_TO_BINS_PATH, __file__)) from e

def main():
    create_tags_to_bins()

    get_tags_to_bins()

    update_metadata(MSRC_TAGS_TO_BINS_PATH,MSRC_API_URL)