"""
An unofficial, RESTful API for NIST's NVD.
Copyright (C) 2020  plasticuproject@pm.me
"""

import gzip
import json
import pathlib
from urllib.error import URLError
from urllib.request import urlopen
from resources.model import Database
from urllib.request import urlretrieve
from dateutil.parser import isoparse as date_parse


# NIST NVD JSON Dump file locations
schema = 'https://csrc.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema'
files = ['https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz',
        'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2021.json.gz',
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
path2 = str(pathlib.Path(__file__).parent.absolute()) + '/../'

def get_meta():

    # get time when modified file was last updated
    metaURL = urlopen('https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta')
    newMetaTime = metaURL.readlines()[0][17:-2].decode()
    with open(path + '/modified.meta', 'w') as outfile:
        outfile.write(newMetaTime)


def get_dumps():

    #look for dump files and retrieve if not found
    schemaPath = pathlib.Path(__file__).parent.absolute() / ('dumps' + schema[41:])
    if not schemaPath.is_file():
        urlretrieve(schema, path + schema[41:])
        get_meta()
    for url in files[2:]:
        urlPath = pathlib.Path(__file__).parent.absolute() / ('dumps' + url[39:])
        if not urlPath.is_file():
            urlretrieve(url, path + url[39:])


def update():

    # download modified and recent dumps
    modifiedFile = path + files[0][39:]
    urlretrieve(files[0], modifiedFile)

    recentFile = path + files[1][39:]
    urlretrieve(files[1], recentFile)
    
    # get time when modified file was last updated
    with open(path + '/modified.meta', 'r') as infile:
        metaTime = infile.read()
    modifiedTime = date_parse(metaTime)

    # make new list of cves to add
    modified = Database().modified(path=path2)
    newModified = [cve for cve in modified if date_parse(cve['lastModifiedDate']) > modifiedTime]

    # get new modified update time
    get_meta()
    
    #organize cves by year
    for year in range(2002, 2022):   # Keep up-to-date with current year
        modifiedCves = []
        for cve in newModified:
            cveYear = cve['cve']['CVE_data_meta']['ID'][4:8]
            if int(cveYear) < 2003:
                cveYear = '2002'
            if cveYear == str(year):
                modifiedCves.append(cve)

        # add cves to files
        if len(modifiedCves) > 0:
            for cveID in modifiedCves:
                cveYear = cveID['cve']['CVE_data_meta']['ID'][4:8]
                ID = cveID['cve']['CVE_data_meta']['ID']
                data = Database().data(cveYear, path=path2)
                [data.remove(cve) for cve in data if ID == cve['cve']['CVE_data_meta']['ID']]
            [data.append(cve) for cve in modifiedCves]
            cveNum = len(data)
            contents = {"CVE_data_type" : "CVE",
                        "CVE_data_format" : "MITRE",
                        "CVE_data_version" : "4.0",
                        "CVE_data_numberOfCVEs" : cveNum,
                        "CVE_data_timestamp" : metaTime,
                        "CVE_Items" : data
                        }

            # write cves to data files
            bytesData = json.dumps(contents).encode('utf-8')
            fileName = '/nvdcve-1.1-' + cveYear + '.json.gz'
            filePath = pathlib.Path(__file__).parent.absolute() / ('dumps' + fileName)
            filePath.unlink()
            file = path + fileName
            with gzip.open(file, 'wb') as datafile:
                datafile.write(bytesData)


if __name__ == "__main__":

    try:
        get_dumps()
        update()
    except URLError as e:
        print(e)
        quit()
