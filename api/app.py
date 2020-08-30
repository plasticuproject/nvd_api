"""
An unofficial, RESTful API for NIST's NVD.
Copyright (C) 2020  plasticuproject@pm.me
"""

from flask import Flask, request
from api.resources import search
from flask_restful import Api
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
api = Api(app)


# Rate Limiting
limiter = Limiter(app, key_func=get_remote_address, default_limits=[
          '50/hour', '200/day'])

rate = limiter.limit('1/second, 5/minute', error_message={
       'Rate Limit Exceeded': '1/second, 5/minutes, 50/hour, 200/day'})

@limiter.request_filter
def ip_whitelist():
    return request.remote_addr == "127.0.0.1"

search.CVE.decorators.append(rate)
search.CVE_Year.decorators.append(rate)
search.CVE_Modified.decorators.append(rate)
search.CVE_Recent.decorators.append(rate)
search.CVE_All.decorators.append(rate)
search.Schema.decorators.append(rate)


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
    
