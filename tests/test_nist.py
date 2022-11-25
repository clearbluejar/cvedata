from datetime import datetime
import random
import requests

from cvedata.nist import get_all_nist_cve_urls,get_cves, NIST_OLDEST_YEAR


def test_nist_urls_available():

    urls = get_all_nist_cve_urls(NIST_OLDEST_YEAR)

    for year,url in urls:
        res = requests.head(url)
        assert res.status_code == 200


def test_cves_from_all_years():

    this_year = datetime.now().year

    cve_list = []

    for year in range(NIST_OLDEST_YEAR,this_year):
        for x in range(200):
            cve_list.append(f"CVE-{year}-{random.randint(0,9999)}")

    full_cves = get_cves(cve_list)

    assert len(cve_list) == len(full_cves)

    