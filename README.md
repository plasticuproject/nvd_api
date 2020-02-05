# nvd_api

An unofficial, RESTful API for NIST's NVD.

## Endpoints are:

**Get results for a specific CVE-ID:** <br />
*https://plasticuproject.pythonanywhere.com/nvd-api/v1/(CVE-ID)* <br />

**Get results for all CVEs:** <br />
*https://plasticuproject.pythonanywhere.com/nvd-api/v1/all* <br />

**Get results for all CVEs in a given year:** <br />
*https://plasticuproject.pythonanywhere.com/nvd-api/v1/year/(YEAR)* <br />

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
*https://plasticuproject.pythonanywhere.com/nvd-api/v1/year/2007?keyword=apache* <br />

## Note:
All endpoint GET requests will return JSON response data.  <br />
Live API database will be updated once every 24 hours, with information from **nvd.nist.gov**.  <br />
Feel free to submit an Issue or Pull Request (with issue reference number)  <br />
if you have any problems.
