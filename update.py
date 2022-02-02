"""
An unofficial, RESTful API for NIST's NVD.
Copyright (C) 2022  plasticuproject@pm.me
"""

import gzip
import json
import pathlib
from sys import exit as sys_exit
from datetime import datetime
from typing import List
from urllib.error import URLError
from urllib.request import urlopen
from urllib.request import urlretrieve
from dateutil.parser import isoparse as date_parse
from api.resources.model import Database

# NIST NVD JSON Dump file locations
SCHEMA: str = ("https://csrc.nist.gov/schema/nvd/feed/1.1/" +
               "nvd_cve_feed_json_1.1.schema")
FILE_URL: str = "https://nvd.nist.gov/feeds/json/cve/1.1/"
FILES: List[str] = [
    FILE_URL + "nvdcve-1.1-modified.json.gz", FILE_URL +
    "nvdcve-1.1-recent.json.gz", FILE_URL + "nvdcve-1.1-2022.json.gz",
    FILE_URL + "nvdcve-1.1-2021.json.gz", FILE_URL + "nvdcve-1.1-2020.json.gz",
    FILE_URL + "nvdcve-1.1-2019.json.gz", FILE_URL + "nvdcve-1.1-2018.json.gz",
    FILE_URL + "nvdcve-1.1-2017.json.gz", FILE_URL + "nvdcve-1.1-2016.json.gz",
    FILE_URL + "nvdcve-1.1-2015.json.gz", FILE_URL + "nvdcve-1.1-2014.json.gz",
    FILE_URL + "nvdcve-1.1-2013.json.gz", FILE_URL + "nvdcve-1.1-2012.json.gz",
    FILE_URL + "nvdcve-1.1-2011.json.gz", FILE_URL + "nvdcve-1.1-2010.json.gz",
    FILE_URL + "nvdcve-1.1-2009.json.gz", FILE_URL + "nvdcve-1.1-2008.json.gz",
    FILE_URL + "nvdcve-1.1-2007.json.gz", FILE_URL + "nvdcve-1.1-2006.json.gz",
    FILE_URL + "nvdcve-1.1-2005.json.gz", FILE_URL + "nvdcve-1.1-2004.json.gz",
    FILE_URL + "nvdcve-1.1-2003.json.gz", FILE_URL + "nvdcve-1.1-2002.json.gz"
]

# Path to dump files
DUMPS_PATH = str(pathlib.Path(__file__).parent.absolute()) + "/api/dumps"
ROOT_PATH = str(pathlib.Path(__file__).parent.absolute()) + "/"

# Current year
YEAR = datetime.now().year


def get_meta() -> None:
    """Get time when modified file was last updated."""
    with urlopen(
            "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta"
    ) as meta_url:
        new_meta_time = meta_url.readlines()[0][17:-2].decode()
    with open(DUMPS_PATH + "/modified.meta", "w", encoding="utf-8") as outfile:
        outfile.write(new_meta_time)


def get_dumps() -> None:
    """Look for dump files and retrieve if not found."""
    schema_path = pathlib.Path(__file__).parent.absolute() / ("dumps" +
                                                              SCHEMA[41:])
    if not schema_path.is_file():
        urlretrieve(SCHEMA, DUMPS_PATH + SCHEMA[41:])
        get_meta()
    for url in FILES[2:]:
        url_path = pathlib.Path(__file__).parent.absolute() / ("dumps" +
                                                               url[39:])
        if not url_path.is_file():
            urlretrieve(url, DUMPS_PATH + url[39:])


# pylint: disable=too-many-locals
def update() -> None:
    """Update all dump files with current CVE information
    from NIST server."""

    # Download modified and recent dumps
    modified_file = DUMPS_PATH + FILES[0][39:]
    urlretrieve(FILES[0], modified_file)

    recent_file = DUMPS_PATH + FILES[1][39:]
    urlretrieve(FILES[1], recent_file)

    # Get time when modified file was last updated
    with open(DUMPS_PATH + "/modified.meta", "r", encoding="utf-8") as infile:
        meta_time = infile.read()
    modified_time = date_parse(meta_time)

    # Make new list of cves to add
    modified = Database().modified(path=ROOT_PATH)
    new_modified = [
        cve for cve in modified
        if date_parse(cve["lastModifiedDate"]) > modified_time
    ]

    # Get new modified update time
    get_meta()

    # Organize cves by year
    for year in range(2002, (YEAR + 1)):
        modified_cves = []
        for cve in new_modified:
            cve_year = cve["cve"]["CVE_data_meta"]["ID"][4:8]
            if int(cve_year) < 2003:
                cve_year = "2002"
            if cve_year == str(year):
                modified_cves.append(cve)

        # Add cves to files
        if len(modified_cves) > 0:
            for cve_id in modified_cves:
                cve_year = cve_id["cve"]["CVE_data_meta"]["ID"][4:8]
                i_d = cve_id["cve"]["CVE_data_meta"]["ID"]
                data = Database().data(cve_year, path=ROOT_PATH)
                _ = [
                    data.remove(cve) for cve in data  # type: ignore
                    if i_d == cve["cve"]["CVE_data_meta"]["ID"]
                ]
            _ = [data.append(cve) for cve in modified_cves]  # type: ignore
            cve_num = len(data)
            contents = {
                "CVE_data_type": "CVE",
                "CVE_data_format": "MITRE",
                "CVE_data_version": "4.0",
                "CVE_data_numberOfCVEs": cve_num,
                "CVE_data_timestamp": meta_time,
                "CVE_Items": data
            }

            # Write cves to data files
            bytes_data = json.dumps(contents).encode("utf-8")
            file_name = "/nvdcve-1.1-" + cve_year + ".json.gz"
            file_path = pathlib.Path(__file__).parent.absolute() / ("dumps" +
                                                                    file_name)
            file_path.unlink()
            file = DUMPS_PATH + file_name
            with gzip.open(file, "wb") as datafile:
                datafile.write(bytes_data)


if __name__ == "__main__":
    try:
        get_dumps()
        update()
    except URLError as e:
        print(e)
        sys_exit()
