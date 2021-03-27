"""
An unofficial, RESTful API for NIST's NVD.
Copyright (C) 2020  plasticuproject@pm.me
"""

import json
import gzip


def return_data(file):

    # Helper function to load database files into memory
    with gzip.open(file, 'rb') as datafile:
        data = json.loads(datafile.read())['CVE_Items']
        return data


class Database:
    """Creates Database instance and loads archived database files
    into memory in dictionary format.
    """

    def data(self, year, path=''):

        # Used to return any or all archived files by year
        file = path + 'api/dumps/nvdcve-1.1-' + year + '.json.gz'
        return return_data(file)


    def modified(self, path=''):

        # Used to return modified archive
        file = path + 'api/dumps/nvdcve-1.1-modified.json.gz'
        return return_data(file)


    def recent(self):

        # Used to return recent archive
        file = 'api/dumps/nvdcve-1.1-recent.json.gz'
        return return_data(file)


    def schema(self):

        # Used to return database schema file 
        file = 'api/dumps/nvd_cve_feed_json_1.1.schema'
        with open(file, 'r') as datafile:
            data = json.loads(datafile.read())
        return data
