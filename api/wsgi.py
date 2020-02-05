"""
An unofficial, RESTful API for NIST's NVD.
Copyright (C) 2020  plasticuproject@pm.me
"""

from api_app import app


# For use with the gunicorn WSGI production server
if __name__ == "__main__":
    app.run()
