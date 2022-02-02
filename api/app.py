"""
An unofficial, RESTful API for NIST's NVD.
Copyright (C) 2022  plasticuproject@pm.me
"""

from flask import Flask, request
from flask_restful import Api
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from api.resources import search

app = Flask(__name__)
api = Api(app)

# Rate Limiting
limiter = Limiter(app,
                  key_func=get_remote_address,
                  default_limits=["50/hour", "200/day"])

rate = limiter.limit("1/second, 5/minute",
                     error_message={
                         "Rate Limit Exceeded":
                         "1/second, 5/minutes, 50/hour, 200/day"
                     })


@limiter.request_filter
def ip_whitelist():  # type: ignore
    """Whitelists host server so it is
    not ratelimited."""
    return request.remote_addr == "127.0.0.1"


search.Cve.decorators.append(rate)
search.CveYear.decorators.append(rate)
search.CveModified.decorators.append(rate)
search.CveRecent.decorators.append(rate)
search.CveAll.decorators.append(rate)
search.CveCpe.decorators.append(rate)
search.Schema.decorators.append(rate)

# API endpoints
api.add_resource(search.Cve, "/nvd-api/v1/<cve_id>")
api.add_resource(search.CveYear, "/nvd-api/v1/year/<year>")
api.add_resource(search.CveModified, "/nvd-api/v1/modified")
api.add_resource(search.CveRecent, "/nvd-api/v1/recent")
api.add_resource(search.CveAll, "/nvd-api/v1/all")
api.add_resource(search.CveCpe, "/nvd-api/v1/cpe/<cpe_version>/<cpe_id>")
api.add_resource(search.Schema, "/nvd-api/v1/schema")

# Binds to local host
# if __name__ == "__main__":
#     app.run(host="0.0.0.0")
