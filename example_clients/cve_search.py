#!/usr/bin/env python3
#Copyright (C) 2020  plasticuproject@pm.me
# 'pip install requests' to use

import requests
from sys import argv
from json.decoder import JSONDecodeError

# API address
url = 'https://plasticuproject.pythonanywhere.com/nvd-api/v1/'


# The main app funtion
def search(*args):

    cves = {}

    # Prints help/usage info
    if len(args) == 1 or args[1] == '-h' or args[1] == '--help':
        print('''\nSearch CVE records by ID, YEAR and/or KEYWORD. Prints ID and description only.\n
        USAGE:
        ./cve_search.py <CVE-ID>
        ./cve_serach.py <year> (keyword)
        ./cve_search.py all (keyword)
        ./cve_search.py recent (keyword)
        ./cve_search.py modified (keyword)
        ''' + '\n')
        quit()

    # Adds CVE ID and description to cves dictionary from results matching CVE-ID queried
    elif len(args) == 2 and args[1].startswith('cve') or args[1].startswith('CVE'):
        cve = args[1]
        res = requests.get(url + cve)
        cves[res.json()['cve']['CVE_data_meta']['ID']] = res.json()['cve']['description']['description_data'][0]['value']

    # Adds CVE ID/s and descriptions/s to cves dictionary from results list if CVEs are found matching criteria
    else:
        date = args[1]
        year = 'year/'
        keyword = ' '.join(args[2:])
        if date == 'all' or date == 'recent' or date == 'modified':
            year = date
            date = ''
        res = requests.get(url + year + date + '?keyword=' + keyword)
        for i in res.json():
            cves[i['cve']['CVE_data_meta']['ID']] = i['cve']['description']['description_data'][0]['value']

    # Prints if no results are found and cves dictionary is empty
    if len(cves) == 0:
        print('No results found.')
        quit()

    # Prints CVE ID/s and description/s from cves dictionary, if any
    for ID, description in cves.items():
        print('\n' + ID)
        print(description + '\n')


if __name__ == '__main__':

    # Run search function and catch all errors and exceptions
    try:
        search(*argv)

    except (KeyError, TypeError):
        user_in = ' '.join(argv[1:])
        print('Did not understand your request for: ' + user_in)
        quit()

    except JSONDecodeError:
        print('NETWORK ERROR: Please check your request or try again later.')
        quit()

    except KeyboardInterrupt:
        quit()


