import os
import json
import time
import pathlib
import pandas as pd
from pandas.io.json import json_normalize

from .config import DATA_DIR
from .cvrf import get_msrc_merged_cvrf_json,MSRC_API_URL
from .metadata import update_metadata

MSRC_TAG_BIN_MAP = os.path.join(DATA_DIR,"msrc-tags-to-bins.json")

def get_tag(notes):

    for note in notes:
        if note['Type'] == 7:
            print(note['Value'])
            return note['Value']

    return None

def get_faq(notes):

    for note in notes:
        if note['Type'] == 7:
            print(note['Value'])
            return note['Value']

    return None


def create_msrc_tag_bin_map():
    #msrc_cvrf_json = get_msrc_merged_cvrf_json()

    #df = pd.DataFrame()
    #for cvrf in 
    #df.append()
    oct_path = pathlib.Path('cvedata/data/.cache/2022-Oct.json')
    oct = json.loads(oct_path.read_text())
    df = json_normalize(oct['Vulnerability'])

    df.to_json('df.json')
    
    FIELDS = ["CVE", "tags"]

    df['tags'] = df["Notes"].apply(lambda x: get_tag(x))

    print(df.head())
    # for d in df["Notes"][0]:
    #     print(d)
    # #print(df["Title.Value"])
    print(df[FIELDS])
    #print(df.head())

    notes_df = pd.DataFrame(df['Notes'].values.tolist())
    print(notes_df)
    
    print("stop")
    # tag_set = set()

    # for cvrf_json in msrc_cvrf_json:
    #     if cvrf_json.get("Vulnerability"):
    #         [tag_set.add(note.get('Value').lower()) for vuln in cvrf_json["Vulnerability"] for note in vuln['Notes']
    #                     if note['Type'] == 7 and note.get('Value')]

    # tag_set = sorted(tag_set)

    # print(f"Found {len(tag_set)} tags")

    # with open(MSRC_TAG_BIN_MAP, 'w') as f:
    #     json.dump(tag_set,f,indent=4)

def get_msrc_tag_bin_json():
    try:
        with open(MSRC_TAG_BIN_MAP) as f:
            return json.load(f)
    except FileNotFoundError as e:
        raise Exception("Missing {}. Please run {}".format(
            MSRC_TAG_BIN_MAP, __file__)) from e

def update():

    print(f"Updating {pathlib.Path(MSRC_TAG_BIN_MAP).name}...")
    
    start = time.time()   
    create_msrc_tag_bin_map()
    elapsed = time.time() - start

    count = len(get_msrc_tags())

    update_metadata(MSRC_TAG_BIN_MAP,{'sources': [MSRC_API_URL], 'generation_time': elapsed,  'count': count})


if __name__ == "__main__":
    update()