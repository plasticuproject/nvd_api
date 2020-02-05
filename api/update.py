"""
An unofficial, RESTful API for NIST's NVD.
Copyright (C) 2020  plasticuproject@pm.me
"""

import pathlib
from urllib.request import urlretrieve


# NIST NVD JSON Dump file locations
schema = 'https://csrc.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema'
files = ['https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2020.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2018.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2017.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2016.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2014.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2013.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2012.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2010.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2009.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2008.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2007.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2006.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2005.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2004.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2003.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.gz']


# Path to dump files
path = str(pathlib.Path(__file__).parent.absolute()) + '/dumps'


def update():

    # updates database files
    urlretrieve(schema, path + schema[41:])
    for url in files:
        urlretrieve(url, path + url[39:])


if __name__ == "__main__":
    update()
