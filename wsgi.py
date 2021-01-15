"""
An unofficial, RESTful API for NIST's NVD.
Copyright (C) 2020  plasticuproject@pm.me
"""

from api.app import app as application


# For use with the gunicorn WSGI production server
if __name__ == "__main__":
    application.run()
