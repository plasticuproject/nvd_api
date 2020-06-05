"""
An unofficial, RESTful API for NIST's NVD.
Copyright (C) 2020  plasticuproject@pm.me
"""

import gzip
import json
import pathlib
from datetime import datetime
from resources.model import Database
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


def get_dumps():

    #look for dump files and retrieve if not found
    schemaPath = pathlib.Path(__file__).parent.absolute() / ('dumps' + schema[41:])
    if not schemaPath.is_file():
        urlretrieve(schema, path + schema[41:])
    for url in files[2:]:
        urlPath = pathlib.Path(__file__).parent.absolute() / ('dumps' + url[39:])
        if not urlPath.is_file():
            urlretrieve(url, path + url[39:])


def update():

    # download modified and recent dump, update dumps with new cve info
    today = str(datetime.now())[:10]
    nowtime = str(datetime.now())[:20].replace(' ', 'T').replace('.', 'Z')
    modifiedFile = path + files[0][39:]
    urlretrieve(files[0], modifiedFile)

    recentFile = path + files[1][39:]
    urlretrieve(files[1], recentFile)

    modified = Database().modified(path='../')

    # This will only grab cves from the modified file that match todays date
    # set slice this date to match your update frequency
    newModified = [cve for cve in modified if cve['lastModifiedDate'][:10] == today]
    
    for year in range(2002, 2021):   # Keep up-to-date with current year
        modifiedCves = []
        for cve in newModified:
            cveYear = cve['cve']['CVE_data_meta']['ID'][4:8]
            if int(cveYear) < 2003:
                cveYear = '2002'

            if cveYear == str(year):
                modifiedCves.append(cve)

        if len(modifiedCves) > 0:
            data = Database().data(str(year), path='../')
            for cve in modifiedCves:
                data.append(cve)
            cveNum = len(data) - 1
            contents = {"CVE_data_type" : "CVE",
                        "CVE_data_format" : "MITRE",
                        "CVE_data_version" : "4.0",
                        "CVE_data_numberOfCVEs" : cveNum,
                        "CVE_data_timestamp" : nowtime,
                        "CVE_Items" : data
                        }

            bytesData = json.dumps(contents).encode('utf-8')
            fileName = '/nvdcve-1.1-' + cveYear + '.json.gz'
            filePath = pathlib.Path(__file__).parent.absolute() / 'dumps' + fileName
            filePath.unlink()
            file = path + fileName
            with gzip.open(file, 'wb') as datafile:
                datafile.write(bytesData)


if __name__ == "__main__":
    get_dumps()
    update()
