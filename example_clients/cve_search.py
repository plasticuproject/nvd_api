#!/usr/bin/env python3
"""Copyright (C) 2022  plasticuproject@pm.me
'pip install requests' to use"""

from sys import argv
from sys import exit as sys_exit
from json.decoder import JSONDecodeError
import requests

# API address
URL = "https://plasticuproject.pythonanywhere.com/nvd-api/v1/"

HELP_TEXT = """
Search CVE records by ID, YEAR and/or KEYWORD. Prints ID and description only.
        \nUSAGE:
        ./cve_search.py <CVE-ID>
        ./cve_serach.py <year> (keyword)
        ./cve_search.py all (keyword)
        ./cve_search.py recent (keyword)
        ./cve_search.py modified (keyword)

"""


def search(*args: str) -> None:
    """Main program function."""

    cves = {}

    # Prints help/usage info
    if len(args) == 1 or args[1] == "-h" or args[1] == "--help":
        print(HELP_TEXT)
        sys_exit()

    # Adds CVE ID and description to cves dictionary from results
    # matching CVE-ID queried
    elif len(args) == 2 and args[1].startswith("cve") or args[1].startswith(
            "CVE"):
        cve = args[1]
        res = requests.get(URL + cve)
        cves[res.json()["cve"]["CVE_data_meta"]["ID"]] = res.json(
        )["cve"]["description"]["description_data"][0]["value"]

    # Adds CVE ID/s and descriptions/s to cves dictionary from results
    # list if CVEs are found matching criteria
    else:
        date = args[1]
        year = "year/"
        keyword = " ".join(args[2:])
        if date in ("all", "recent", "modified"):
            year = date
            date = ""
        res = requests.get(URL + year + date + "?keyword=" + keyword)
        for i in res.json():
            cves[i["cve"]["CVE_data_meta"]["ID"]] = i["cve"]["description"][
                "description_data"][0]["value"]

    # Prints if no results are found and cves dictionary is empty
    if len(cves) == 0:
        print("No results found.")
        sys_exit()

    # Prints CVE ID/s and description/s from cves dictionary, if any
    for i_d, description in cves.items():
        print("\n" + i_d)
        print(description + "\n")

    # Prints number of results
    if len(cves) > 1:
        print("Results found:", str(len(cves)))
        print()


if __name__ == "__main__":

    # Run search function and catch all errors and exceptions
    try:
        search(*argv)

    except (KeyError, TypeError):
        USER_IN = " ".join(argv[1:])
        print("Did not understand your request for: " + USER_IN)
        sys_exit()

    except JSONDecodeError:
        print("NETWORK ERROR: Please check your request or try again later.")
        sys_exit()

    except KeyboardInterrupt:
        sys_exit()
