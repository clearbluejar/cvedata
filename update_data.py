import cve_data.cvrf as cvrf
from cve_data.cwe import main as cwe_update
from cve_data.msrc_tags import main as msrc_tags_update
from cve_data.win_bin_map import main as win_bin_map_update

from cve_data.tags_to_bins import main as tags_to_bins_update
from cve_data.nist import main as nist_update
import cve_data.metadata as metadata
import cve_data.chromerelease as chromerelease
import cve_data.acknowledgements as acks1

import os
import pathlib

# cvrf.create_msrc_merged_cvrf_json()
# cvrf.get_msrc_merged_cvrf_json()

# cwe_update()
# msrc_tags_update()
# win_bin_map_update()
msrc_tags_update()

import time

start = time.time()
print("hello")
#tags_to_bins_update()
msrc_tags_update()
end = time.time()
print(end - start)

# chromerelease.build_chromerelease_json()

# acks1.build_acknowledgements()

for file in metadata.get_metadata_json():
    print(file)

