"""
An unofficial, RESTful API for NIST's NVD.
Copyright (C) 2020  plasticuproject@pm.me
"""

from flask import Flask
from api.resources import search
from flask_restful import Api


app = Flask(__name__)
api = Api(app)


# API endpoints
api.add_resource(search.CVE, '/nvd-api/v1/<cve_id>')
api.add_resource(search.CVE_Year, '/nvd-api/v1/year/<year>')
api.add_resource(search.CVE_Modified, '/nvd-api/v1/modified')
api.add_resource(search.CVE_Recent, '/nvd-api/v1/recent')
api.add_resource(search.CVE_All, '/nvd-api/v1/all')
api.add_resource(search.Schema, '/nvd-api/v1/schema')


# Binds to local host
#if __name__ == '__main__':
    #app.run(host='0.0.0.0')
    
