import json
import pathlib
import datetime
import json

from . config import METADATA_PATH

def get_metadata_json() -> dict:

    data_file_json = {}

    if pathlib.Path(METADATA_PATH).exists():
        with open(METADATA_PATH) as f:
            data_file_json = json.load(f)

    return data_file_json

def print_stats():
    print(json.dumps(get_metadata_json(), indent=4))

def update_metadata(path,meta):
    """
    Updates metadata.json with details related to data_file
    """

    path = pathlib.Path(path)

    data_file_json = {}
    name = path.name
    size = path.stat().st_size
    last_modified = datetime.datetime.fromtimestamp(path.stat().st_mtime)

    if pathlib.Path(METADATA_PATH).exists():
        with open(METADATA_PATH) as f:
            data_file_json = json.load(f)

    # if data_file_json.get(name):     
    data_file_json[name] = {}
    data_file_json[name]['size'] = size
    data_file_json[name]['last_modified'] = last_modified.isoformat()
    data_file_json[name]['meta'] = meta

    data_file_json['last_modified'] = datetime.datetime.now().isoformat()

    with open(METADATA_PATH, "w") as f:
        json.dump(data_file_json,f,indent=4)

def should_update(path, days_ago: int ) -> bool:

    should_update = True

    path = pathlib.Path(path)

    # check file actually exists
    if path.exists():

        # make sure this is a metadata file to read
        if pathlib.Path(METADATA_PATH).exists():
            with open(METADATA_PATH) as f:
                data_file_json = json.load(f)

            # make sure metadata contains an entry for path
            if data_file_json.get(path.name):                   

                path_mod_date = datetime.datetime.fromisoformat(data_file_json[path.name]['last_modified'])
                delta = datetime.datetime.now() - path_mod_date
                
                if delta.days <= days_ago:
                    should_update = False
                        

    return should_update
        
