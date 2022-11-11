# cvedata

<img align="center" src="https://user-images.githubusercontent.com/3752074/201245258-2de3e9f4-2097-4fbd-b01f-06ebd9d835cf.jpg">
</p>

<p align="center">
<a href="https://twitter.com/clearbluejar"><img align="center" src="https://img.shields.io/twitter/follow/clearbluejar?color=blue&style=for-the-badge"></a> 
  <img align="center" src="https://img.shields.io/github/stars/clearbluejar/cvedata?style=for-the-badge">
</p>

## About

A collection of CVE and related data. This python package is caught somewhere between a data collection tool and a CVE data API. Much more the former than the latter.

## Docs 

- https://clearbluejar.github.io/cvedata/

## Generated Data

| Generated File                         | size     | last_modified              | count | gen_time  | skip_book | sources                                                                                                   | key_index | swap_axes | normalize |
|----------------------------------------|----------|----------------------------|-------|-----------|-----------|-----------------------------------------------------------------------------------------------------------|-----------|-----------|-----------|
| msrc_cvrf_merged.json.gz               | 4497761  | 2022-10-25T11:23:22.392199 | 79    | 99.5073   | True      | [’https://api.msrc.microsoft.com/’]                                                                       | nan       | nan       | nan       |
| chromerelease_raw_cve.json             | 410724   | 2022-10-25T11:25:15.957757 | 2309  | 111.108   | False     | [’https://chromereleases.googleblog.com’]                                                                 |           | 1         | 0         |
| chromerelease_cve.json                 | 805382   | 2022-10-25T11:25:16.053758 | 2309  | 0.0973854 | False     | [’https://chromereleases.googleblog.com’]                                                                 | cve_id    | 0         | 1         |
| researcher_names.json                  | 259408   | 2022-10-25T11:25:16.085759 | 3190  | 0.0235612 | False     | [’https://chromereleases.googleblog.com’, ‘https://api.msrc.microsoft.com/’]                              |           | 0         | 0         |
| researcher_names_grouped.json          | 326265   | 2022-10-25T11:25:16.125759 | 1862  | 0.0389409 | False     | [’https://chromereleases.googleblog.com’, ‘https://api.msrc.microsoft.com/’]                              |           | 1         | 1         |
| researcher_twitter_map.json            | 83462    | 2022-10-25T11:25:16.157760 | 1862  | 0.0288165 | False     | [’https://chromereleases.googleblog.com’, ‘https://api.msrc.microsoft.com/’]                              |           | 1         | 0         |
| researcher_cve_map.json                | 366039   | 2022-10-25T11:25:27.289898 | 1862  | 11.1312   | False     | [’https://chromereleases.googleblog.com’, ‘https://api.msrc.microsoft.com/’]                              |           | 0         | 0         |
| cwe.json.gz                            | 22733    | 2022-10-25T11:25:28.957921 | 1402  | 1.67045   | False     | [’https://cwe.mitre.org/data/xml/cwec_latest.xml.zip’]                                                    |           | 1         | 0         |
| winbindex-desc-to-bins-map.json        | 876088   | 2022-10-25T11:28:07.764445 | 9061  | 160.652   | False     | [’https://github.com/m417z/winbindex/archive/refs/heads/gh-pages.zip’]                                    |           | 1         | 1         |
| winbindex-kb-to-bins-map.json.gz       | 1179899  | 2022-10-25T11:28:08.372451 | 656   | 160.652   | False     | [’https://github.com/m417z/winbindex/archive/refs/heads/gh-pages.zip’]                                    |           | 1         | 1         |
| winbindex-versions-to-bins-map.json.gz | 806818   | 2022-10-25T11:28:09.584464 | 5475  | 160.652   | False     | [’https://github.com/m417z/winbindex/archive/refs/heads/gh-pages.zip’]                                    |           | 1         | 1         |
| msrc-tags-merged.json                  | 13810    | 2022-10-25T11:28:09.752465 | 431   | 0.0185909 | False     | [’https://api.msrc.microsoft.com/’]                                                                       |           | 0         | 0         |
| msrc-tags-merged-frequency.json        | 15190    | 2022-10-25T11:28:09.752465 | 431   | 0.0185909 | False     | [’https://api.msrc.microsoft.com/’]                                                                       |           | 1         | 1         |
| msrc-tags-to-bins.json                 | 301366   | 2022-10-25T11:29:04.929149 | 431   | 55.1729   | False     | [’https://github.com/m417z/winbindex/archive/refs/heads/gh-pages.zip’, ‘https://api.msrc.microsoft.com/’] |           | 1         | 1         |
| nist_merged_cve.json.gz                | 25463422 | 2022-10-25T11:29:43.689757 | 7     | 39.5711   | True      | [’https://nvd.nist.gov/feeds/json/cve/1.1/’]                                                              | nan       | nan       | nan       |
| msrc-cvrf-pandas-merged.json.gz        | 255582   | 2022-10-25T11:30:30.226375 | 7     | 23.8023   | False     | [’https://api.msrc.microsoft.com/’]                                                                       |           | 0         | 0         |


## Project Using Data

- [cve-markdown-charts](https://github.com/clearbluejar/cve-markdown-charts) - A simple tool to create mermaid js markdown charts from CVE IDs and CVE keyword searches.
- More Coming soon...

## Inspired By

- [WinBinDex](https://winbindex.m417z.com/) 
- [Security-Datasets](https://github.com/OTRF/Security-Datasets)