"""
An unofficial, RESTful API for NIST's NVD.
Copyright (C) 2022  plasticuproject@pm.me
"""

import json
import gzip
from typing import Any, List, Dict


def _return_data(file: str) -> List[Dict[str, Any]]:
    """Helper function to load database files into memory."""
    data: List[Dict[str, Any]]
    with gzip.open(file, "rb") as datafile:
        data = json.loads(datafile.read())["CVE_Items"]
    return data


class Database:
    """Creates Database instance and loads archived database files
    into memory in dictionary format."""
    file: str

    @staticmethod
    def data(year: str, path: str = "") -> List[Dict[str, Any]]:
        """Used to return any or all archived files by year."""
        file = path + "api/dumps/nvdcve-1.1-" + year + ".json.gz"
        return _return_data(file)

    @staticmethod
    def modified(path: str = "") -> List[Dict[str, Any]]:
        """Used to return modified archive."""
        file = path + "api/dumps/nvdcve-1.1-modified.json.gz"
        return _return_data(file)

    @staticmethod
    def recent() -> List[Dict[str, Any]]:
        """Used to return recent archive."""
        file = "api/dumps/nvdcve-1.1-recent.json.gz"
        return _return_data(file)

    @staticmethod
    def schema() -> Dict[str, Any]:
        """Used to return database schema file."""
        file = "api/dumps/nvd_cve_feed_json_1.1.schema"
        with open(file, "r", encoding="utf-8") as datafile:
            data: Dict[str, Any] = json.loads(datafile.read())
        return data
