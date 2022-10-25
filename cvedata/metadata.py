import json
from datetime import datetime
import json
from pathlib import Path

from . config import METADATA_PATH

def get_metadata_json() -> dict:

    data_file_json = {}

    if pathlib.Path(METADATA_PATH).exists():
        with open(METADATA_PATH) as f:
            data_file_json = json.load(f)

    return data_file_json

def print_stats():
    print(json.dumps(get_metadata_json(), indent=4))

def update_metadata(path,meta: dict,count: int,gen_time: datetime,key_index=None,swap_axes=None,normalize=None):
    """
    Updates metadata.json with details related to data_file
    """

    path = Path(path)

    data_file_json = {}
    name = path.name
    size = path.stat().st_size
    last_modified = datetime.fromtimestamp(path.stat().st_mtime)

    if Path(METADATA_PATH).exists():
        with open(METADATA_PATH) as f:
            data_file_json = json.load(f)

    data_file_json[name] = {}
    data_file_json[name]['size'] = size
    data_file_json[name]['last_modified'] = last_modified.isoformat()
    data_file_json[name]['count'] = count
    data_file_json[name]['gen_time'] = gen_time
    
    # if any are set, code will be generated for display
    if key_index is not None or swap_axes is not None or normalize is not None:
        data_file_json[name]['key_index'] = key_index
        data_file_json[name]['swap_axes'] = swap_axes if swap_axes else False
        data_file_json[name]['normalize'] = normalize if normalize else False
        data_file_json[name]['skip_book'] = False
    else:
        data_file_json[name]['skip_book'] = True
    
    for item in meta:
        data_file_json[name][item] = meta[item]

    data_file_json['last_modified'] = datetime.now().isoformat()

    with open(METADATA_PATH, "w") as f:
        json.dump(data_file_json,f,indent=4)

def should_update(path, days_ago: int ) -> bool:

    should_update = True

    path = Path(path)

    # check file actually exists
    if path.exists():

        # make sure this is a metadata file to read
        if Path(METADATA_PATH).exists():
            with open(METADATA_PATH) as f:
                data_file_json = json.load(f)

            # make sure metadata contains an entry for path
            if data_file_json.get(path.name):                   

                path_mod_date = datetime.fromisoformat(data_file_json[path.name]['last_modified'])
                delta = datetime.now() - path_mod_date
                
                if delta.days <= days_ago:
                    should_update = False                        

    return should_update
        
