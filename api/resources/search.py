"""
An unofficial, RESTful API for NIST's NVD.
Copyright (C) 2022  plasticuproject@pm.me
"""

from datetime import datetime
from typing import Dict, Any, List, Callable, Optional
from flask_restful import Resource, abort
from webargs import fields
from webargs.flaskparser import use_args
from .model import Database

# Current year
YEAR = datetime.now().year

# Sets variable name for keyword search parameter
keyword: Dict[str, Any] = {
    "keyword": fields.List(fields.Str(missing=""))
}
location: str = "query"


def return_result(data: Callable[..., List[Dict[str, Any]]],
                  *args: str) -> List[Dict[str, Any]]:
    """Helper function to return CVE JSON data."""
    result: List[Dict[str, Any]] = []
    if len(args) == 0:
        for cve in data():
            result.append(cve)
    elif len(args) == 1:
        for cve in data(args[0]):  # lgtm[py/call/wrong-arguments]
            result.append(cve)
    return result


def keyword_search(value: List[str],
                   result: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Helper function to parse results for keyword
    argument in CVE description."""
    keyword_results: List[Dict[str, Any]] = []
    keyword_list: List[str] = [_.lower() for _ in value]
    for cve in result:
        for description in cve["cve"]["description"]["description_data"]:
            if all(_ in description["value"].lower() for _ in keyword_list):
                keyword_results.append(cve)
    return keyword_results


def cpe_search(value: str,
               result: List[Dict[str, Any]],
               version: str = "23") -> List[Dict[str, Any]]:
    """Helper function to search for results with
    a matching CPE value."""
    results: List[Dict[str, Any]] = []

    def find_leaves(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Recursive function to obtain all configuration leaves of a CVE"s
        configuration nodes."""
        leaves: List[Dict[str, Any]] = []
        for subnode in nodes:
            if "children" in subnode.keys() and len(subnode["children"]) > 0:
                leaves += find_leaves(subnode["children"])
            elif "cpe_match" in subnode.keys():
                leaves += find_leaves(subnode["cpe_match"])
            else:
                leaves.append(subnode)
        return leaves

    for cve in result:
        if "configurations" in cve and "nodes" in cve["configurations"]:
            leaves = find_leaves(cve["configurations"]["nodes"])
            for leaf in leaves:
                key = "cpe" + version + "Uri"
                if key in leaf.keys() and value in leaf[key]:
                    results.append(cve)
    return results


def check_year(year: str) -> None:
    """Helper function to make sure the input year is valid."""
    try:
        int(year)
    except ValueError:
        abort(404, message="No such endpoint exists")


class Cve(Resource):
    """Initiates the Database class, loads the correct CVE year archive
    file in memory and returns the CVE data in the file matching the given
    CVE-ID in a JSON response via a GET request.
    """

    # For the rate limiter decorator
    decorators: List[Any] = []

    @staticmethod
    def get(cve_id: str) -> Optional[Dict[str, Any]]:
        """GET method for Cve endpoint."""
        cve_id = cve_id.upper()
        data = Database().data
        year: str = cve_id[4:8]
        cve_data: Optional[Dict[str, Any]] = None
        check_year(year)
        if int(year) > 2002:
            for cve in data(year):
                if cve["cve"]["CVE_data_meta"]["ID"] == cve_id:
                    cve_data = cve
        elif int(year) <= 2002:
            for cve in data("2002"):
                if cve["cve"]["CVE_data_meta"]["ID"] == cve_id:
                    cve_data = cve
        if not cve_data:
            abort(404, message="No matching CVE-ID found.")
        return cve_data


class CveYear(Resource):
    """Initiates the Database class, loads the correct CVE year archive
    file in memory and returns all CVE data in the file matching the given
    year and keyword argument in a JSON response via a GET request.
    If no keyword is given it will return all CVEs in the file.
    """

    # For the rate limiter decorator
    decorators: List[Any] = []

    @staticmethod
    @use_args(keyword, location=location)
    def get(args: Dict[str, List[str]], year: str) -> List[Dict[str, Any]]:
        """GET method for CveYear endpoint."""
        year_result: List[Dict[str, Any]]
        result: List[Dict[str, Any]] = []
        data = Database().data
        check_year(year)
        if int(year) > 2002:
            year_result = return_result(data, year)
        elif int(year) < 2003:
            year_result = []
            for cve in data("2002"):
                if cve["cve"]["CVE_data_meta"]["ID"][4:8] == str(year):
                    year_result.append(cve)
        if args:
            keyed = keyword_search(args["keyword"], year_result)
            if keyed:
                result.append(keyed[0])
        else:
            return year_result
        return result


class CveModified(Resource):
    """Initiates the Database class, loads the "modified" archive file in
    memory and returns all CVE data in the file matching the given
    keyword argument in a JSON response via a GET request. If no keyword
    is given it will return all CVEs in the file.
    """

    # For the rate limiter decorator
    decorators: List[Any] = []

    @staticmethod
    @use_args(keyword, location=location)
    def get(args: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """GET method for CveModified endpoint."""
        modified = Database().modified
        result: List[Dict[str, Any]] = return_result(modified)
        if args:
            return keyword_search(args["keyword"], result)
        return result


class CveRecent(Resource):
    """Initiates the Database class, loads the "recent" archive file in
    memory and returns all CVE data in the file matching the given
    keyword argument in a JSON response via a GET request. If no keyword
    is given it will return all CVEs in the file.
    """

    # For the rate limiter decorator
    decorators: List[Any] = []

    @staticmethod
    @use_args(keyword, location=location)
    def get(args: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """GET method for CveRecent endpoint."""
        recent = Database().recent
        result: List[Dict[str, Any]] = return_result(recent)
        if args:
            return keyword_search(args["keyword"], result)
        return result


class CveAll(Resource):
    """Initiates the Database class, loads all CVE year archive files in
    memory and returns all the CVE data in those files matching the given
    keyword argument in a JSON response via a GET request. If no keyword
    is given it will return all CVEs in the file.
    """

    # For the rate limiter decorator
    decorators: List[Any] = []

    @staticmethod
    @use_args(keyword, location=location)
    def get(args: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """GET method for CveAll endpoint."""
        result: List[Dict[str, Any]] = []
        data = Database().data
        for year in range(2002, (YEAR + 1)):
            for cve in data(str(year)):
                if args:
                    keyed = keyword_search(args["keyword"], [cve])
                    if keyed:
                        result.append(keyed[0])
                else:
                    result.append(cve)
        return result


class CveCpe(Resource):
    """Initiates the Database class, loads all CVE archive
    file in memory and returns all CVE data in the file matching the given
    CPE-ID and keyword argument in a JSON response via a GET request.
    If no keyword is given it will return all CVEs matching the CPE-ID.
    Besides the CPE-ID, also the CPE-Version (23/24/etc.) must be specified.
    """

    # For the rate limiter decorator
    decorators: List[Any] = []

    @staticmethod
    @use_args(keyword, location=location)
    def get(args: Dict[str, List[str]], cpe_version: str,
            cpe_id: str) -> List[Dict[str, Any]]:
        """GET method for CveCpe endpoint."""
        result: List[Dict[str, Any]] = []
        data = Database().data
        for year in range(2002, (YEAR + 1)):
            for cve in data(str(year)):
                if args:
                    keyed = keyword_search(args["keyword"], [cve])
                    if keyed:
                        result.append(keyed[0])
                else:
                    result.append(cve)
        return cpe_search(cpe_id, result, version=str(cpe_version))


class Schema(Resource):
    """Initiates the Database class, loads the schema file in memory and
    returns the database schema contents in a JSON response via a GET request.
    """

    # For the rate limiter decorator
    decorators: List[Any] = []

    @staticmethod
    def get() -> Dict[str, Any]:
        """GET method for Schema endpoint."""
        schema = Database().schema
        return schema()
