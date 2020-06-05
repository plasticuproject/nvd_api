[![Build Status](https://travis-ci.org/plasticuproject/nvd_api.svg?branch=master)](https://travis-ci.org/plasticuproject/nvd_api)
[![GPLv3 license](https://img.shields.io/badge/License-GPLv3-blue.svg)](http://perso.crans.org/besson/LICENSE.html)
[![Coverage Status](https://coveralls.io/repos/github/plasticuproject/nvd_api/badge.svg?branch=master)](https://coveralls.io/github/plasticuproject/nvd_api?branch=master)
# nvd_api

An unofficial, RESTful API for NIST's NVD.

## Endpoints with examples:

**Get results for a specific CVE-ID:** <br />
*https://plasticuproject.pythonanywhere.com/nvd-api/v1/CVE-2010-4662* <br />

**Get results for all CVEs:** *(Not recommended, you should refine your search.)* <br />
*https://plasticuproject.pythonanywhere.com/nvd-api/v1/all* <br />

**Get results for all CVEs in a given year:** <br />
*https://plasticuproject.pythonanywhere.com/nvd-api/v1/year/2020* <br />

**Get results for all recently added CVEs (last 8 days):** <br />
*https://plasticuproject.pythonanywhere.com/nvd-api/v1/recent* <br />

**Get results for all recently modified and added CVEs (last 8 days):** <br />
*https://plasticuproject.pythonanywhere.com/nvd-api/v1/modified* <br />

**Return the database schema:** <br />
*https://plasticuproject.pythonanywhere.com/nvd-api/v1/schema* <br />

## Keyword Search 
**For endpoints:** <br />
*../all* <br />
*../year/(YEAR)* <br />
*../recent* <br />
*../modified* <br />
you can also add a keyword search parameter to return only CVEs with <br />
that keyword found in the description, for example:  <br />
*https://plasticuproject.pythonanywhere.com/nvd-api/v1/year/2019?keyword=sudo* <br />

## Note:
All endpoint GET requests will return JSON response data.  <br />
Live API database will be updated once every 24 hours, with information from **nvd.nist.gov**.  <br />
Feel free to submit an Issue or Pull Request (with issue reference number)  <br />
if you have any problems. <br />

## Development / Self Hosting
If you plan on contributing, developing, or hosting yourself, be sure to run the <br />
`update.py` script at least once every 24 hours. Failure to do this will cause the <br />
database to loose sync. If this happens just delete all the dump files in `api/dumps` <br />
and run `update.py` to reinstall them. <br />

## Example Python Client
In the *example_clients* directory there is a simple python CLI client that lets you <br />
search for CVEs and print their CVE-ID and Description to screen. This is just an example <br />
of how you could write an application and interface this API. <br />
```
user@ubuntu:~$ ./nvd_api/example_clients/cve_search.py --help

Search CVE records by ID, YEAR and/or KEYWORD. Prints ID and description only.

        USAGE:
        ./cve_search.py <CVE-ID>
        ./cve_serach.py <year> (keyword)
        ./cve_search.py all (keyword)
        ./cve_search.py recent (keyword)
        ./cve_search.py modified (keyword)
```
