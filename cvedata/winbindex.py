import os
import re
import gzip
import json
import requests
import zipfile
from io import BytesIO
from datetime import datetime
from pathlib import Path
import time
import pandas as pd

from .config import DATA_DIR,CACHE_PATH
from .metadata import update_metadata
from .util import get_file_json

WINBINDEX_ZIP_EXTRACT_PATH = Path(CACHE_PATH,"winbindex")
WINBINDEX_ZIP_EXTRACT_PATH.mkdir(exist_ok=True,parents=True)
WINBINDEX_ZIP_FILES_DATA_PATH = Path("winbindex-gh-pages","data","by_filename_compressed")
WINBINDEX_FILES_DATA_PATH = Path(WINBINDEX_ZIP_EXTRACT_PATH,WINBINDEX_ZIP_FILES_DATA_PATH)
WINBINDEX_GITHUB_URL = "https://github.com/m417z/winbindex/archive/refs/heads/gh-pages.zip"
WINBINDEX_ZIP_PATH = Path(WINBINDEX_ZIP_EXTRACT_PATH,WINBINDEX_GITHUB_URL.split('/')[-1])


WINDOWS_FILE_DESCRIPTION_TO_BINS_PATH = Path(DATA_DIR,"winbindex-desc-to-bins-map.json")
WINDOWS_KBS_TO_BINS_PATH = Path(DATA_DIR,"winbindex-kb-to-bins-map.json.gz")
WINDOWS_VERSION_TO_BINS_PATH = Path(DATA_DIR,"winbindex-versions-to-bins-map.json.gz")
WINDOWS_VER_TO_BUILD_PATH = Path(DATA_DIR,"winbindex-winver-to-build-map.json")
WB_PANDAS_PATH = Path(DATA_DIR,"winbindex-fileinfo-pandas.json.gz")

def open_gz_json(path):    
    
    with gzip.GzipFile(path,"r") as f:        
        return json.loads(f.read())           

def unzip_path(source_filename, dest_dir,path):
    if not path.endswith('/'):
        path += '/'
    with zipfile.ZipFile(source_filename) as zf:
        for file in zf.namelist():
            if file.startswith(path):
                zf.extract(file, dest_dir)

def download_and_extract_from_url(url,extract_path):
    """
    Download and extract binary data files from winbindex
    """
    download = True

    # Use cached file unless outdated
    if WINBINDEX_ZIP_PATH.exists() and WINBINDEX_ZIP_PATH.stat().st_size > 0:
        current_day = datetime.now().day
        mod_time = datetime.fromtimestamp(WINBINDEX_ZIP_PATH.stat().st_mtime)
        if mod_time.day == current_day:
            print("{} already up to date.".format(WINBINDEX_ZIP_PATH))
            download = False
    
    if download:
        print(f'Downloading {url} ')
        response = requests.get(url)
        print('Download complete')

        assert response.status_code == 200

        with open(WINBINDEX_ZIP_PATH, 'wb') as f:
            f.write(response.content)

        # extracting the zip file contents
        unzip_path(WINBINDEX_ZIP_PATH.as_posix(),extract_path,WINBINDEX_ZIP_FILES_DATA_PATH.as_posix())

def create_winbindex_maps():

    # uses WinBinDiff data to map fileinfo description tags to binary names to build 
    download_and_extract_from_url(WINBINDEX_GITHUB_URL,WINBINDEX_ZIP_EXTRACT_PATH)

    desc_to_bins = {}
    kb_to_bins = {}
    ver_to_bins = {}
    winver_to_build = {}

    files = os.listdir(WINBINDEX_FILES_DATA_PATH)
    total = len(files)
    count = 0
    failed_load = []
    wb_pandas = {}

    print(f"Processing {total} files..")
    for i,file in enumerate(sorted(files)):

        # if count > 1000:
        #     break
        
        if re.search('(exe|dll|sys|winmd|cpl|ax|node|ocx|efi|acm|scr|tsp|drv)\.json\.gz',file):
            try: 
                file_json = open_gz_json(os.path.join(WINBINDEX_FILES_DATA_PATH,file))
            except json.JSONDecodeError as e:
                failed_load.append(file)
                continue
            
            count += 1
            print(f"{int((count / i)*100)}% : {count} : {file}")
            for bin in file_json:

                filename = file.replace('.json.gz','')
                
                if file_json[bin].get('fileInfo'):
                    file_json[bin]['fileInfo']['filename'] = filename.lower()
                    wb_pandas[bin] = file_json[bin]['fileInfo']

                    if file_json[bin]['fileInfo'].get('description'):
                        desc_to_bins.setdefault(file_json[bin]['fileInfo']['description'],[])                        
                        if filename not in desc_to_bins[file_json[bin]['fileInfo']['description']]:
                            desc_to_bins[file_json[bin]['fileInfo']['description']].append(filename)

                if file_json[bin].get('windowsVersions'):
                    for ver in file_json[bin]['windowsVersions'].keys():
                        for update in file_json[bin]['windowsVersions'][ver]:
                            
                            # don't add BASE 
                            if update == 'BASE':
                                continue

                            winver_to_build.setdefault(ver,set())
                            
                            kb_to_bins.setdefault(update,{})
                            kb_to_bins[update].setdefault('updated',set())
                            kb_to_bins[update].setdefault('versions',set()).add(ver)
                            if file_json[bin]['windowsVersions'][ver][update].get('updateInfo'):
                                kb_ver = file_json[bin]['windowsVersions'][ver][update]['updateInfo']['releaseVersion']
                                kb_to_bins[update]['release'] = file_json[bin]['windowsVersions'][ver][update]['updateInfo']['releaseDate']
                                kb_to_bins[update]['url'] = file_json[bin]['windowsVersions'][ver][update]['updateInfo']['updateUrl']
                                kb_to_bins[update]['build'] = kb_ver
                                winver_to_build[ver].add(kb_ver)
                                
                                #assert len(file_json[bin]['windowsVersions'][ver][update]['assemblies']) <= 3
                                for assem in file_json[bin]['windowsVersions'][ver][update]['assemblies']:
                                    for assemId in file_json[bin]['windowsVersions'][ver][update]['assemblies'][assem]:
                                        #print(file_json[bin]['windowsVersions'][ver][update]['assemblies'][assem]['assemblyIdentity']['version'])
                                        assem_ver = file_json[bin]['windowsVersions'][ver][update]['assemblies'][assem]['assemblyIdentity']['version']
                                        chopped_assem_ver = '.'.join(assem_ver.split('.')[-2:])
                                        #print(kb_ver)
                                        if chopped_assem_ver == kb_ver: # ver # set filename # Build == kb_ver
                                            kb_to_bins[update]['updated'].add(filename)
                                #assert len(file_json[bin]['windowsVersions'][ver][update]['windowsVersionInfo']) == 2
                            else:
                                #print(file_json[bin]['windowsVersions'][ver][update]['windowsVersionInfo'])
                                assert len(file_json[bin]['windowsVersions'][ver][update]['windowsVersionInfo']) == 2
                            #print(file_json[bin]['windowsVersions'][ver][update]['updateinfo']'releaseVersion')
                            #if file_json[bin]['windowsVersions'][ver][update].get()
                            

                                                
                if file_json[bin].get('fileInfo') and file_json[bin]['fileInfo'].get('version'):
                    ver = file_json[bin]['fileInfo']['version'].split()[0]
                    ver_to_bins.setdefault(ver,set())
                    ver_to_bins[ver].add(filename)

    for file in failed_load:
        print(f"failed to load {file}")

    print(f"Processed {count} files of {total}")

    print(f"Sorting {WINDOWS_FILE_DESCRIPTION_TO_BINS_PATH}")
    desc_to_bins = {k: sorted(desc_to_bins[k]) for k in sorted(desc_to_bins,key=lambda x: x, reverse=True)}

    print(f"Sorting {WINDOWS_KBS_TO_BINS_PATH} of length {len(kb_to_bins)}")
    kb_to_bins = {k: kb_to_bins[k] for k in sorted(kb_to_bins,key=lambda x: x, reverse=True)}

    print(f"Sorting {WINDOWS_VERSION_TO_BINS_PATH}")
    ver_to_bins = {k: sorted(list(ver_to_bins[k])) for k in sorted(ver_to_bins,key=lambda x: x, reverse=True)}

    # convert sets to lists
    for k in kb_to_bins:
        kb_to_bins[k]['updated'] = list(kb_to_bins[k]['updated'])
        kb_to_bins[k]['versions'] = list(kb_to_bins[k]['versions'])

    for k in winver_to_build:
        winver_to_build[k] = list(winver_to_build[k])

    # write out results
    with open(WINDOWS_VER_TO_BUILD_PATH, 'w') as f:
        json.dump(winver_to_build,f,indent=4)

    with open(WINDOWS_FILE_DESCRIPTION_TO_BINS_PATH, 'w') as f:
        json.dump(desc_to_bins,f,indent=4)

    with gzip.open(WINDOWS_KBS_TO_BINS_PATH, "w") as f:
        f.write(json.dumps(kb_to_bins).encode("utf-8"))

    with gzip.open(WINDOWS_VERSION_TO_BINS_PATH, "w") as f:
        f.write(json.dumps(ver_to_bins).encode("utf-8"))

    all_wb_pandas_df = pd.DataFrame.from_dict(wb_pandas,orient='index')
    all_wb_pandas_df.to_json(WB_PANDAS_PATH)

def get_winbindex_desc_to_bin_map():
    return get_file_json(WINDOWS_FILE_DESCRIPTION_TO_BINS_PATH,__file__)

def get_winbindex_kbs_to_bin_map():
    return get_file_json(WINDOWS_KBS_TO_BINS_PATH,__file__)

def get_winbindex_ver_to_bin_map():
    return get_file_json(WINDOWS_VERSION_TO_BINS_PATH,__file__)

def get_winbindex_ver_to_build_map():
    return get_file_json(WINDOWS_VER_TO_BUILD_PATH,__file__)
    

def update():

    print(f"Updating {WINDOWS_FILE_DESCRIPTION_TO_BINS_PATH}...")
    print(f"Updating {WINDOWS_KBS_TO_BINS_PATH}...")
    print(f"Updating {WINDOWS_VERSION_TO_BINS_PATH}...")
    
    start = time.time()
    create_winbindex_maps()
    elapsed = time.time() - start
    
    count = len(get_winbindex_desc_to_bin_map())
    update_metadata(WINDOWS_FILE_DESCRIPTION_TO_BINS_PATH,{'sources': [WINBINDEX_GITHUB_URL]},count,elapsed,swap_axes=True,normalize=True)

    count = len(get_winbindex_kbs_to_bin_map())
    update_metadata(WINDOWS_KBS_TO_BINS_PATH,{'sources': [WINBINDEX_GITHUB_URL]},count,elapsed,swap_axes=True)
    
    count = len(get_winbindex_ver_to_bin_map())
    update_metadata(WINDOWS_VERSION_TO_BINS_PATH,{'sources': [WINBINDEX_GITHUB_URL]},count,elapsed,swap_axes=True,normalize=True)

    count = len(get_winbindex_ver_to_build_map())
    update_metadata(WINDOWS_VER_TO_BUILD_PATH,{'sources': [WINBINDEX_GITHUB_URL]},count,elapsed,swap_axes=False,normalize=True)

    

if __name__ == "__main__":
    update()





    
