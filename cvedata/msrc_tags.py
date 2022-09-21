import os
import json
import time
import pathlib

from .config import DATA_DIR
from .cvrf import get_msrc_merged_cvrf_json,MSRC_API_URL
from .metadata import update_metadata

MSRC_TAGS_PATH = os.path.join(DATA_DIR,"msrc-tags-merged.json")

def create_msrc_tags():
    msrc_cvrf_json = get_msrc_merged_cvrf_json()

    tag_set = set()

    for cvrf_json in msrc_cvrf_json:
        if cvrf_json.get("Vulnerability"):
            [tag_set.add(note.get('Value').lower()) for vuln in cvrf_json["Vulnerability"] for note in vuln['Notes']
                        if note['Type'] == 7 and note.get('Value')]

    tag_set = sorted(tag_set)

    print(f"Found {len(tag_set)} tags")

    with open(MSRC_TAGS_PATH, 'w') as f:
        json.dump(tag_set,f,indent=4)

def get_msrc_tags():
    try:
        with open(MSRC_TAGS_PATH) as f:
            return json.load(f)
    except FileNotFoundError as e:
        raise Exception("Missing {}. Please run {}".format(
            MSRC_TAGS_PATH, __file__)) from e

def update():

    print(f"Updating {pathlib.Path(MSRC_TAGS_PATH).name}...")
    
    start = time.time()   
    create_msrc_tags()
    elapsed = time.time() - start

    count = len(get_msrc_tags())

    update_metadata(MSRC_TAGS_PATH,{'sources': [MSRC_API_URL], 'generation_time': elapsed,  'count': count})


if __name__ == "__main__":
    update()