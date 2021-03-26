"""
An unofficial, RESTful API for NIST's NVD.
Copyright (C) 2020  plasticuproject@pm.me
"""

from flask_restful import Resource, abort
from .model import Database
from webargs import fields
from webargs.flaskparser import use_args


# Sets variable name for keyword search parameter
keyword = {'keyword' : fields.Str(missing='')}


def return_result(set, *args):

    # Helper function to return CVE JSON data
    result = []
    if len(args) == 0:
        for cve in set():
            result.append(cve)
    elif len(args) == 1:
        for cve in set(args[0]):
            result.append(cve)
    return result


def keyword_search(value, result):

    # Helper function to parse results for keyword argument in CVE description
    keyword_results = []
    for cve in result:
        for description in cve['cve']['description']['description_data']:
            if value in description['value'].lower():
                keyword_results.append(cve)
    return keyword_results

def cpe_search(value, result, version: str='23'):
    """
    Helper function to search for results with a matching CPE value
    """
    results = []
    def find_leaves(nodes):
        """
        Recursive function to obtain all configuration leaves of a CVE's
        configuration nodes.
        """
        leaves = []
        for subnode in nodes:
            if 'children' in subnode.keys():
                leaves += find_leaves(subnode['children'])
            elif 'cpe_match' in subnode.keys():
                leaves += find_leaves(subnode['cpe_match'])
            else:
                leaves.append(subnode)
        return leaves

    for cve in result:
        if 'configurations' not in cve:
            continue
        if 'nodes' not in cve['configurations']:
            continue
        leaves = find_leaves(cve['configurations']['nodes'])
        for leaf in leaves:
            key = 'cpe' + version + 'Uri'
            if key in leaf.keys():
                if value in leaf[key]:
                    results.append(cve)
    return results



def check_year(year):

    # Helper function to make sure the input year is valid
    try:
        int(year)
    except ValueError:
        abort(404, message='No such endpoint exists')


class CVE(Resource):
    """Initiates the Database class, loads the correct CVE year archive
    file in memory and returns the CVE data in the file matching the given
    CVE-ID in a JSON response via a GET request.
    """

    # For the rate limiter decorator
    decorators = []

    def get(self,cve_id):
        cve_id = cve_id.upper()
        data = Database().data
        year = cve_id[4:8]
        check_year(year)
        if int(year) > 2002:
            for cve in data(year):
                if cve['cve']['CVE_data_meta']['ID'] == cve_id:
                    return cve
        elif int(year) <= 2002:
            for cve in data('2002'):
                if cve['cve']['CVE_data_meta']['ID'] == cve_id:
                    return cve


class CVE_Year(Resource):
    """Initiates the Database class, loads the correct CVE year archive
    file in memory and returns all CVE data in the file matching the given
    year and keyword argument in a JSON response via a GET request.
    If no keyword is given it will return all CVEs in the file.
    """

    # For the rate limiter decorator
    decorators = []

    @use_args(keyword)
    def get(self, args, year):
        data = Database().data
        check_year(year)
        if int(year) > 2002:
            result = return_result(data, year)
        elif int(year) < 2003:
            result = []
            for cve in data('2002'):
                if cve['cve']['CVE_data_meta']['ID'][4:8] == str(year):
                    result.append(cve)
        if args['keyword'] == '':
            return result
        return keyword_search(args['keyword'].lower(), result)


class CVE_Modified(Resource):
    """Initiates the Database class, loads the 'modified' archive file in
    memory and returns all CVE data in the file matching the given
    keyword argument in a JSON response via a GET request. If no keyword
    is given it will return all CVEs in the file.
    """

    # For the rate limiter decorator
    decorators = []

    @use_args(keyword)
    def get(self, args):
        modified = Database().modified
        result = return_result(modified)
        if args['keyword'] == '':
            return result
        return keyword_search(args['keyword'].lower(), result)
        

class CVE_Recent(Resource):
    """Initiates the Database class, loads the 'recent' archive file in
    memory and returns all CVE data in the file matching the given
    keyword argument in a JSON response via a GET request. If no keyword
    is given it will return all CVEs in the file.
    """

    # For the rate limiter decorator
    decorators = []

    @use_args(keyword)
    def get(self, args):
        recent = Database().recent
        result = return_result(recent)
        if args['keyword'] == '':
            return result
        return keyword_search(args['keyword'].lower(), result)


class CVE_All(Resource):
    """Initiates the Database class, loads all CVE year archive files in
    memory and returns all the CVE data in those files matching the given
    keyword argument in a JSON response via a GET request. If no keyword
    is given it will return all CVEs in the file.
    """

    # For the rate limiter decorator
    decorators = []

    @use_args(keyword)
    def get(self, args):
        result = []
        data = Database().data
        for year in range(2002, 2022):  # Keep up-to-date with current year
            for cve in data(str(year)):
                result.append(cve)
        if args['keyword'] == '':
            return result
        return keyword_search(args['keyword'].lower(), result)


class CVE_CPE(Resource):
    """Initiates the Database class, loads all CVE archive
    file in memory and returns all CVE data in the file matching the given
    CPE-ID and keyword argument in a JSON response via a GET request.
    If no keyword is given it will return all CVEs matching the CPE-ID.
    Besides the CPE-ID, also the CPE-Version (23/24/etc.) must be specified.
    """

    # For the rate limiter necorator
    decorators = []

    @use_args(keyword)
    def get(self, args, cpe_version, cpe_id):
        result = []
        data = Database().data
        for year in range(2002, 2022):  # Keep up-to-date with current year
            for cve in data(str(year)):
                result.append(cve)
        if args['keyword'] != '':
            result = keyword_search(args['keyword'].lower(), result)
        return cpe_search(cpe_id, result, version=str(cpe_version))


class Schema(Resource):
    """Initiates the Database class, loads the schema file in memory and
    returns the database schema contents in a JSON response via a GET request.
    """

    # For the rate limiter decorator
    decorators = []

    def get(self):
        schema = Database().schema
        return schema()

