import time

from .msrc_cvrf import update as cvrf_update
from .msrc_tags import update as msrc_tags_update
from .chromerelease import update as chromerelease_update
from .acknowledgements import update as ack_update
from .cwe import update as cwe_update
from .winbindex import update as winbindex_update
from .metadata import print_stats
from .nist import update as nist_update
from .msrc_pandas import update as msrc_pandas_update
from .win_verinfo import update as verinfo_update



def update_all_data():

    print("Updating all data...")
    start = time.time()

    # Windows
    cvrf_update()    
    msrc_pandas_update()
    msrc_tags_update()
    winbindex_update()
    verinfo_update()

    # Chrome
    chromerelease_update()

    # CVEs
    nist_update()
    cwe_update()    
    ack_update()
    

    elapsed = time.time() - start

    print_stats()
    print(f"Updated all data in {elapsed} seconds")


if __name__ == "__main__":
    update_all_data()
