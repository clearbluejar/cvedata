import os
import re
import gzip
import json
import requests
import zipfile
from io import BytesIO
from datetime import datetime

from .config import DATA_DIR,CACHE_PATH
from .metadata import update_metadata

WINBINDEX_ZIP_EXTRACT_PATH = os.path.join(CACHE_PATH,"winbindex")
WINBINDEX_ZIP_FILES_DATA_PATH = os.path.join("winbindex-gh-pages","data","by_filename_compressed")
WINBINDEX_FILES_DATA_PATH = os.path.join(WINBINDEX_ZIP_EXTRACT_PATH,WINBINDEX_ZIP_FILES_DATA_PATH)
WINBINDEX_GITHUB_URL = "https://github.com/m417z/winbindex/archive/refs/heads/gh-pages.zip"
WINBINDEX_ZIP_PATH = os.path.join(CACHE_PATH,WINBINDEX_GITHUB_URL.split('/')[-1])


WINDOWS_FILE_DESCRIPTION_TO_BINS_PATH = os.path.join(DATA_DIR,"win-desc-to-bins-map.json")
WINDOWS_KBS_TO_BINS_PATH = os.path.join(DATA_DIR,"win-kb-to-bins-map.json.gz")
WINDOWS_VERSION_TO_BINS_PATH = os.path.join(DATA_DIR,"win-versions-to-bins-map.json.gz")

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
    if os.path.exists(WINBINDEX_ZIP_PATH) and os.path.getsize(WINBINDEX_ZIP_PATH) > 0:
        current_day = datetime.now().day
        mod_time = datetime.fromtimestamp(os.path.getmtime(WINBINDEX_ZIP_PATH))    
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
        unzip_path(WINBINDEX_ZIP_PATH,extract_path,WINBINDEX_ZIP_FILES_DATA_PATH)

def create_win_bin_maps():

    if not os.path.exists(CACHE_PATH):
        os.mkdir(CACHE_PATH)

    # uses WinBinDiff data to map fileinfo description tags to binary names to build 
    download_and_extract_from_url(WINBINDEX_GITHUB_URL,WINBINDEX_ZIP_EXTRACT_PATH)

    desc_to_bins = {}
    kb_to_bins = {}
    ver_to_bins = {}

    total = len(os.listdir(WINBINDEX_FILES_DATA_PATH))
    count = 0

    print(f"Processing {total} files..")
    for i,file in enumerate(os.listdir(WINBINDEX_FILES_DATA_PATH)):
        
        if re.search('exe|dll|sys|winmd|cpl|ax|node|ocx|efi|acm|scr|tsp|drv',file):
            file_json = open_gz_json(os.path.join(WINBINDEX_FILES_DATA_PATH,file))
            count += 1
            for bin in file_json:

                filename = file.replace('.json.gz','')

                if file_json[bin].get('fileInfo'):
                    if file_json[bin]['fileInfo'].get('description'):
                        desc_to_bins.setdefault(file_json[bin]['fileInfo']['description'],[])                        
                        if filename not in desc_to_bins[file_json[bin]['fileInfo']['description']]:
                            desc_to_bins[file_json[bin]['fileInfo']['description']].append(filename)

                if file_json[bin].get('windowsVersions'):
                    for ver in file_json[bin]['windowsVersions'].keys():
                        for update in file_json[bin]['windowsVersions'][ver]:
                            kb_to_bins.setdefault(update,set())
                            if file_json[bin]['windowsVersions'][ver][update].get('updateInfo'):
                                kb_ver = file_json[bin]['windowsVersions'][ver][update]['updateInfo']['releaseVersion']
                                #assert len(file_json[bin]['windowsVersions'][ver][update]['assemblies']) <= 3
                                for assem in file_json[bin]['windowsVersions'][ver][update]['assemblies']:
                                    for assemId in file_json[bin]['windowsVersions'][ver][update]['assemblies'][assem]:
                                        #print(file_json[bin]['windowsVersions'][ver][update]['assemblies'][assem]['assemblyIdentity']['version'])
                                        assem_ver = file_json[bin]['windowsVersions'][ver][update]['assemblies'][assem]['assemblyIdentity']['version']
                                        chopped_assem_ver = '.'.join(assem_ver.split('.')[-2:])
                                        #print(kb_ver)
                                        if chopped_assem_ver == kb_ver:
                                            kb_to_bins[update].add(filename + '-' + assem_ver)
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


    print(f"Processed {count} files of {total}")

    print(f"Sorting {WINDOWS_FILE_DESCRIPTION_TO_BINS_PATH}")
    desc_to_bins = {k: sorted(desc_to_bins[k]) for k in sorted(desc_to_bins,key=lambda x: x, reverse=True)}

    print(f"Sorting {WINDOWS_KBS_TO_BINS_PATH}")
    kb_to_bins = {k: sorted(list(kb_to_bins[k])) for k in sorted(kb_to_bins,key=lambda x: x, reverse=True)}

    print(f"Sorting {WINDOWS_VERSION_TO_BINS_PATH}")
    ver_to_bins = {k: sorted(list(ver_to_bins[k])) for k in sorted(ver_to_bins,key=lambda x: x, reverse=True)}

    with open(WINDOWS_FILE_DESCRIPTION_TO_BINS_PATH, 'w') as f:
        json.dump(desc_to_bins,f,indent=4)

    with gzip.open(WINDOWS_KBS_TO_BINS_PATH, "w") as f:
        f.write(json.dumps(kb_to_bins).encode("utf-8"))

    with gzip.open(WINDOWS_VERSION_TO_BINS_PATH, "w") as f:
        f.write(json.dumps(ver_to_bins).encode("utf-8"))

def get_win_desc_to_bin_map():
        try:
            with open(WINDOWS_FILE_DESCRIPTION_TO_BINS_PATH) as f:
                return json.load(f)
        except FileNotFoundError as e:
            raise Exception("Missing {}. Please run {}".format(
                WINDOWS_FILE_DESCRIPTION_TO_BINS_PATH, __file__)) from e

def get_win_kbs_to_bin_map():
        try:
            with gzip.open(WINDOWS_KBS_TO_BINS_PATH) as f:
                return json.load(f)
        except FileNotFoundError as e:
            raise Exception("Missing {}. Please run {}".format(
                WINDOWS_KBS_TO_BINS_PATH, __file__)) from e

def get_win_ver_to_bin_map():
        try:
            with gzip.open(WINDOWS_VERSION_TO_BINS_PATH) as f:
                return json.load(f)
        except FileNotFoundError as e:
            raise Exception("Missing {}. Please run {}".format(
                WINDOWS_VERSION_TO_BINS_PATH, __file__)) from e

def main():
    create_win_bin_maps()

    get_win_desc_to_bin_map()

    get_win_kbs_to_bin_map()

    update_metadata(WINDOWS_FILE_DESCRIPTION_TO_BINS_PATH,WINBINDEX_GITHUB_URL)

    update_metadata(WINDOWS_KBS_TO_BINS_PATH,WINBINDEX_GITHUB_URL)


if __name__ == "__main__":
    main()





    
