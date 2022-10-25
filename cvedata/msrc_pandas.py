from curses.ascii import isdigit
import os
import json
import time
import pandas as pd
from datetime import datetime
from pathlib import Path


from .config import DATA_DIR, PANDAS_DIR
from .msrc_cvrf import get_msrc_merged_cvrf_json,get_msrc_merged_cvrf_json_keyed,MSRC_API_URL
from .metadata import update_metadata
from .msrc_tags import get_tags_desc_to_bins
from .util import get_file_json

MSRC_CVRF_PANDAS = Path(DATA_DIR,"msrc-cvrf-pandas-merged.json.gz")

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

    if row['Tags']:
        tag = row['Tags'].lower()

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

def create_msrc_cvrf_pandas():

    msrc_merged_json = get_msrc_merged_cvrf_json_keyed()

    cvrf_dfs = []
    
    for cvrf_id in msrc_merged_json:
        
        print(f"Processing {cvrf_id}")
        
        df_update = pd.json_normalize(msrc_merged_json[cvrf_id])
        df_vulns = pd.json_normalize(msrc_merged_json[cvrf_id]['Vulnerability'])

        FIELDS = ["Initial Release", "Tags", "Impact", "Max CVSS", "KBs", "Versions", "Acks"]

        df_vulns['Tags'] = df_vulns["Notes"].apply(get_tag)
        df_vulns['FAQs'] = df_vulns["Notes"].apply(get_faqs)
        df_vulns['KBs'] = df_vulns["Remediations"].apply(get_kbs)
        df_vulns['Versions'] = df_vulns["Remediations"].apply(get_versions)
        df_vulns['Impact'] = df_vulns['Threats'].apply(get_types)
        df_vulns['CVRF ID'] = df_update['DocumentTracking.Identification.ID.Value'].values[0]    
        df_vulns['Initial Release'] = datetime.strftime(datetime.fromisoformat(df_update['DocumentTracking.InitialReleaseDate'].values[0].replace('Z','')),'%Y-%m-%d')
        df_vulns['Current Release'] = datetime.strftime(datetime.fromisoformat(df_update['DocumentTracking.CurrentReleaseDate'].values[0].replace('Z','')),'%Y-%m-%d')
        df_vulns['Acks'] = df_vulns['Acknowledgments'].apply(get_acks)
        df_vulns['Max CVSS'] = df_vulns['CVSSScoreSets'].apply(get_cvss_base)
        df_vulns['Bins'] = df_vulns[['Tags','KBs','Versions']].apply(get_bins,axis=1)

        
        df_vulns.set_index('CVE',inplace=True,verify_integrity=True)
        print(df_vulns[FIELDS].head())

        panda_md_path = PANDAS_DIR / f"{cvrf_id}-pandas.md"
        with panda_md_path.open('w') as f:
            f.write(f"# {cvrf_id}\n\n")
            df_vulns[FIELDS].to_markdown(f,tablefmt="github")

        df_vulns[FIELDS].to_json(PANDAS_DIR / f"{cvrf_id}-pandas.json" )

        print(df_vulns.head())
        cvrf_dfs.append(df_vulns)

    all_cvrf_df = pd.concat(cvrf_dfs)

    all_cvrf_df[FIELDS].to_json(MSRC_CVRF_PANDAS)
    print(all_cvrf_df.head())
    


def get_msrc_cvrf_pandas_json():
    return get_file_json(MSRC_CVRF_PANDAS,__file__)

def update():

    print(f"Updating {MSRC_CVRF_PANDAS}...")
    
    start = time.time()   
    create_msrc_cvrf_pandas()
    elapsed = time.time() - start

    count = len(get_msrc_cvrf_pandas_json())

    update_metadata(MSRC_CVRF_PANDAS,{'sources': [MSRC_API_URL]}, count, elapsed, normalize=False)


if __name__ == "__main__":
    update()