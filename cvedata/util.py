import requests
import shutil
import zipfile
import io
import gzip
import json
from pathlib import Path


def get_file_json(path: Path, base: str) -> dict:
    """
    Open path and return json
    """
    try:
        if path.name.endswith(".gz"):
            with gzip.open(path) as f:
                return json.load(f)
        else:
            with open(path) as f:
                return json.load(f)
    except FileNotFoundError as e:
        raise Exception(
            f"Missing {path}. \nPlease run {base} or download release data: python -m cvedata.download") from e


# from https://techoverflow.net/2018/01/16/downloading-reading-a-zip-file-in-memory-using-python/


def download_extract_zip_mem(url: str):
    """
    Download a ZIP file and extract its contents in memory
    yields (filename, file-like object) pairs
    """
    response = requests.get(url)
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as thezip:
        for zipinfo in thezip.infolist():
            with thezip.open(zipinfo) as thefile:
                yield zipinfo.filename, thefile


# https://svaderia.github.io/articles/downloading-and-unzipping-a-zipfile/

def download_extract_zip_to_path(url: str, path: Path):
    """
    Download zip file and extract to path
    """

    response = requests.get(url)
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as thezip:
        thezip.extractall(path)


def download_extra_zip_to_path_flat(url: str, path: Path):

    # https://stackoverflow.com/questions/46954626/extract-zip-file-without-folder-python

    response = requests.get(url)
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.content)) as thezip:

        for file in thezip.namelist():

            # skip dirs
            if file.endswith('/'):
                continue

            file_path = Path(path / Path(file).name)
            print(f"Extracting {file} to {file_path}")

            file_data_obj = thezip.open(file)

            with file_path.open('wb') as f:
                shutil.copyfileobj(file_data_obj, f)
