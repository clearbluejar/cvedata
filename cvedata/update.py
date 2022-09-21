import time 

from .cvrf import update as cvrf_update
from .msrc_tags import update as msrc_tags_update
from .chromerelease import update as chromerelease_update
from .acknowledgements import update as ack_update
from .cwe import update as cwe_update
from .winbindex import update as winbindex_update
from .tags_to_bins import update as tags_to_bins_update
from .metadata import print_stats
from .nist import update as nist_update

def update_all_data():

    print("Updating all data...")
    start = time.time()

    cvrf_update()
    msrc_tags_update()
    chromerelease_update()
    ack_update()
    cwe_update()
    winbindex_update()
    tags_to_bins_update()
    nist_update()

    elapsed = time.time() - start

    
    print_stats()
    print(f"Updated all data in {elapsed} seconds")
    
if __name__ == "__main__":
    update_all_data()
