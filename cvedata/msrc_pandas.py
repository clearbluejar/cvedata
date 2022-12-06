from curses.ascii import isdigit
import os
import json
import time
import pandas as pd
from datetime import datetime
from pathlib import Path
import difflib


from .config import CACHE_PATH, DATA_DIR
from .msrc_cvrf import get_msrc_merged_cvrf_json_keyed,MSRC_API_URL
from .metadata import should_update, update_metadata
from .util import get_file_json

MSRC_CVRF_PANDAS = Path(DATA_DIR,"msrc-pandas-cvrf-merged.json.gz")
MSRC_CVRF_PANDAS_FULL = Path(DATA_DIR,"msrc-pandas-cvrf-merged-full.json.gz")
MSRC_CVRF_PANDAS_PRODUCTS = Path(DATA_DIR,"msrc-pandas-cvrf-products-map.json.gz")

MSRC_CVE_TAGS_TITLE = Path(DATA_DIR,"msrc-pandas-tag-title.json")

MSRC_TAGS_PATH = Path(DATA_DIR,"msrc-pandas-tags-merged.json")
MSRC_TAGS_FREQ_PATH = Path(DATA_DIR,"msrc-pandas-tags-merged-frequency.json")
MSRC_TITLES_PATH = Path(DATA_DIR,"msrc-pandas-titles-merged.json")
MSRC_TITLES_FREQ_PATH = Path(DATA_DIR,"msrc-pandas-titles-merged-frequency.json")

ALL_KBS_VERSION_MAP = Path(CACHE_PATH,"msrc-pandas-all-msrc-kb-ver-pandas.json") # temporary cache file
MSRC_KB_VERSION = Path(DATA_DIR,"msrc-pandas-kb-ver.json")


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
            faq = note['Value'].replace('\n','') # remove new lines            
            faqs.append(faq)            

    return faqs

def get_kb(rem):
    """
    MSRC List of KBs related to CVE
    """

    #TODO add URLS
    #TODO add version numbers

    kb = None

    if isinstance(rem,dict):
    
        if rem['Description'].get('Value'):
            kb_num = rem['Description']['Value']
            if str(kb_num).isdigit():
                # if rem.get('URL'):
                #     kb = f"[KB{kb}]({rem['URL']})"
                kb = f"KB{kb_num}"

    return kb


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


# def get_bins(row):
   
#     bins = []

#     td_to_bin_map = get_tags_desc_to_bins()

#     # TODO user version and KBs to sharpen bins list

#     if row['Tag']:
#         tag = row['Tag'].lower()

#         if td_to_bin_map.get(tag):
#             for bin in td_to_bin_map[tag]:
#                 bins.append(bin)


#     return ' '.join(bins)

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

def get_products(items, prod_map):
    """
    Map Product IDs to Product Names
    """

    product_names = []

    for item in items:
        if item.get('ProductID'):
            for id in item['ProductID']:
                product_names.append(prod_map[id]['product'])

    return product_names

def get_product_types(items, prod_map):
    """
    Map Product IDs to Product Names
    """

    product_types = []

    for item in items:
        if item.get('ProductID'):
            for id in item['ProductID']:
                product_types.append(prod_map[id]['category'])

    return list(set(product_types))

# Utility functions
def clean_impact(tag):
    if not tag or not isinstance(tag,str):
        return ''
    import re
    #tag = tag.lower()
    if len(tag.split()) > 2:
        tag = re.sub('remote code execution|information disclosure|elevation of privilege|tampering|spoofing|denial of service|security feature bypass|vulnerability|memory corruption', '', tag,flags=re.I)        

    tag = re.sub('[^\. 0-9a-zA-Z]+', '', tag)

    return tag.strip()

def create_msrc_cvrf_pandas():

    FIELDS = ["Initial Release", "Tag", "Title", "Impact", "CVSS", "KBs", "Products", "Versions", "Acks"]

    #if should_update(MSRC_CVRF_PANDAS_FULL,1):
    if True:

        msrc_merged_json = get_msrc_merged_cvrf_json_keyed()

        cvrf_dfs = []
        products_dfs = []
        
        for cvrf_id in msrc_merged_json:
            
            print(f"Processing {cvrf_id}")
            
            df_update = pd.json_normalize(msrc_merged_json[cvrf_id])
            print(df_update.columns)
            df_vulns = pd.json_normalize(msrc_merged_json[cvrf_id]['Vulnerability'])
            print(df_vulns.columns)


            product_cat = {}

            prods = df_update['ProductTree.Branch'].to_dict()[0][0]

            assert len(prods) == 3

            for item in prods['Items']:
                category = item['Name']
                for prod in item['Items']:
                    product_cat[prod['ProductID']] = { 'product': prod['Value'], 'category': category }

            full_prods = df_update['ProductTree.FullProductName'].to_dict()[0]

            # Ensure full product tree matches branch
            for fp in full_prods:
                assert product_cat[fp['ProductID']]['product'] == fp['Value']
            
            prods_df = pd.DataFrame().from_dict(product_cat,orient='index')
            prods_df = prods_df.reset_index(names='id')
            print(prods_df.head())
            products_dfs.append(prods_df)

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
            df_vulns['Products'] = df_vulns['ProductStatuses'].apply(get_products, args=(product_cat,))
            df_vulns['Product Types'] = df_vulns['ProductStatuses'].apply(get_product_types, args=(product_cat,))            
            df_vulns['Title'] = df_vulns['Title.Value'].apply(clean_impact)
            
            df_vulns.set_index('CVE',inplace=True,verify_integrity=True)
            print(df_vulns[FIELDS].head())

            # panda_md_path = PANDAS_DIR / f"{cvrf_id}-pandas.md"
            # with panda_md_path.open('w') as f:
            #     f.write(f"# {cvrf_id}\n\n")
            #     df_vulns[FIELDS].to_markdown(f,tablefmt="github")

            # df_vulns[FIELDS].to_json(PANDAS_DIR / f"{cvrf_id}-pandas.json" )

            print(df_vulns[FIELDS].head())

            cvrf_dfs.append(df_vulns)

        all_cvrf_df = pd.concat(cvrf_dfs)
        all_products_df = pd.concat(products_dfs)
    else:
        all_cvrf_df = pd.read_json(MSRC_CVRF_PANDAS_FULL)
        all_products_df = pd.read_json(MSRC_CVRF_PANDAS_PRODUCTS)

    all_cvrf_df[FIELDS].to_json(MSRC_CVRF_PANDAS)
    all_cvrf_df.to_json(MSRC_CVRF_PANDAS_FULL)

    all_products_df = all_products_df.groupby(by='id').aggregate(lambda x: list(set(x)))
    all_products_df.to_json(MSRC_CVRF_PANDAS_PRODUCTS)

def create_msrc_tags_titles():
    
    all_cvrf_df = pd.read_json(MSRC_CVRF_PANDAS)

    # tag to title
    tags_df = all_cvrf_df[['Tag','Title']]
    tags_title_df = tags_df.reset_index().groupby(['Tag','Title']).aggregate(set)    
    print(tags_title_df.head())
    copy_tags_df = tags_df.copy()
    tags_df['MSRC Count'] = tags_df['Tag'].apply(lambda x: len(copy_tags_df[copy_tags_df['Tag'] == x]))
    tags_df = tags_df.groupby('Tag').aggregate(set)
    
    tags_df['Title'] = tags_df['Title'].aggregate(list)
    tags_df['MSRC Count'] = tags_df['MSRC Count'].apply(lambda x: list(x)[0])
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
    
def get_msrc_tags() -> list:
    return get_file_json(MSRC_TAGS_PATH, __file__)

def get_msrc_tags_freq():
    return get_file_json(MSRC_TAGS_FREQ_PATH, __file__)
    
def get_msrc_titles() -> list:
    return get_file_json(MSRC_TITLES_PATH, __file__)

def get_msrc_titles_freq():
    return get_file_json(MSRC_TITLES_FREQ_PATH, __file__)    

def get_msrc_cvrf_pandas_json():
    return get_file_json(MSRC_CVRF_PANDAS,__file__)

def get_msrc_cvrf_pandas_df():
    return get_file_json(MSRC_CVRF_PANDAS,__file__)

def get_msrc_cvrf_pandas_full_json():
    return get_file_json(MSRC_CVRF_PANDAS_FULL,__file__)

def get_msrc_cvrf_pandas_products_json():
    return get_file_json(MSRC_CVRF_PANDAS_PRODUCTS,__file__)       

def get_msrc_tags_titles_json():
    return get_file_json(MSRC_CVE_TAGS_TITLE,__file__)
    
def get_kb_ver_json():
    return get_file_json(MSRC_KB_VERSION,__file__)

def update():

    print(f"Updating {MSRC_CVRF_PANDAS} and {MSRC_CVRF_PANDAS_FULL}...")
    
    start = time.time()   
    create_msrc_cvrf_pandas()
    elapsed = time.time() - start

    count = len(get_msrc_cvrf_pandas_json())
    update_metadata(MSRC_CVRF_PANDAS,{'sources': [MSRC_API_URL]}, count, elapsed, normalize=False)
    update_metadata(MSRC_CVRF_PANDAS_FULL,{'sources': [MSRC_API_URL]}, count, elapsed, normalize=False)

    count = len(get_msrc_cvrf_pandas_products_json())
    update_metadata(MSRC_CVRF_PANDAS_PRODUCTS,{'sources': [MSRC_API_URL]}, count, elapsed, normalize=False)    

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