import os
import json

from .config import DATA_DIR
from .cvrf import get_msrc_merged_cvrf_json,MSRC_API_URL
from .metadata import update_metadata

MSRC_TAGS_PATH = os.path.join(DATA_DIR,"msrc-merged-all-tags.json")

def create_msrc_tags():
    msrc_cvrf_json = get_msrc_merged_cvrf_json()

    tag_set = set()

    for cvrf_json in msrc_cvrf_json:
        if cvrf_json.get("Vulnerability"):
            [tag_set.add(note.get('Value').lower()) for vuln in cvrf_json["Vulnerability"] for note in vuln['Notes']
                        if note['Type'] == 7 and note.get('Value')]

    tag_set = sorted(tag_set)

    for tag in tag_set:
        print(tag)

    with open(MSRC_TAGS_PATH, 'w') as f:
        json.dump(tag_set,f,indent=4)

def get_msrc_tags():
    try:
        with open(MSRC_TAGS_PATH) as f:
            return json.load(f)
    except FileNotFoundError as e:
        raise Exception("Missing {}. Please run {}".format(
            MSRC_TAGS_PATH, __file__)) from e

def main():

    create_msrc_tags()

    get_msrc_tags()

    update_metadata(MSRC_TAGS_PATH,MSRC_API_URL)


if __name__ == "__main__":
    main()