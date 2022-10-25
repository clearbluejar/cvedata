import json
import gzip
import xmltodict
import os
import time
from pathlib import Path

from .config import DATA_DIR
from .metadata import update_metadata
from .util import get_file_json

# download https://cwe.mitre.org/data/xml/cwec_latest.xml.zip and unzip for CI
CWE_JSON_PATH = Path(DATA_DIR,'cwe.json.gz')
CWE_XML_DOWNLOAD_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

# from https://techoverflow.net/2018/01/16/downloading-reading-a-zip-file-in-memory-using-python/
import requests
import io
import zipfile

def download_extract_zip(url):
    """
    Download a ZIP file and extract its contents in memory
    yields (filename, file-like object) pairs
    """
    response = requests.get(url)
    with zipfile.ZipFile(io.BytesIO(response.content)) as thezip:
        for zipinfo in thezip.infolist():
            with thezip.open(zipinfo) as thefile:
                yield zipinfo.filename, thefile


def create_cwe_json():
    cwes_d = {}

    cwe_file = None
    cwe_xml_zip = download_extract_zip(CWE_XML_DOWNLOAD_URL)

    for name,data in cwe_xml_zip:
        cwe_file = name
        cwe_xml_data = data.read()

    dict_from_xml = xmltodict.parse(cwe_xml_data)

    # grab CWE file metadata
    for key in dict_from_xml['Weakness_Catalog']:
        if '@' in key:
            cwes_d[key] = dict_from_xml['Weakness_Catalog'][key]

    for weak in dict_from_xml['Weakness_Catalog']['Weaknesses']['Weakness']:
        # cwes.append([weak['@ID'],weak['@Name'],'Weakness'])
        cwes_d[weak['@ID']] = {'Name': weak['@Name'], 'Type': 'Weakness'}

    for cat in dict_from_xml['Weakness_Catalog']['Categories']['Category']:
        # cwes.append([cat['@ID'],cat['@Name'],'Category'])
        cwes_d[cat['@ID']] = {'Name': cat['@Name'], 'Type': 'Category'}

    for view in dict_from_xml['Weakness_Catalog']['Views']['View']:
        # cwes.append([view['@ID'],view['@Name'],'View'])
        cwes_d[view['@ID']] = {'Name': view['@Name'], 'Type': 'View'}


    with gzip.open(CWE_JSON_PATH, 'w') as f:
        f.write(json.dumps(cwes_d).encode("UTF-8"))

    print("Created {} with len {}".format(CWE_JSON_PATH,len(cwes_d)))

def get_cwe_json():
    return get_file_json(CWE_JSON_PATH,__file__)

def update():

    print(f"Updating {CWE_JSON_PATH}...")
    
    start = time.time()
    create_cwe_json()
    elapsed = time.time() - start
    count = len(get_cwe_json())
    update_metadata(CWE_JSON_PATH,{'sources': [CWE_XML_DOWNLOAD_URL]},count,elapsed,swap_axes=True)

    print("Loaded {} with length {}".format(CWE_JSON_PATH, count))

    

if __name__ == "__main__":
    update()