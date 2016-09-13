#!/usr/bin/env python

import datetime
import json
import time
import uuid

import jwt

from flask import request, make_response, render_template
from flask.ext.restful import reqparse, Resource

from google.appengine.ext import ndb

EPOCH = datetime.datetime.utcfromtimestamp(0)

ATTRIBUTES = "https://aaf.edu.au/attributes"

HTML_HEADERS = {"Content-Type": "text/html"}

VERIFY = reqparse.RequestParser()
VERIFY.add_argument("secret", required=True)

ENDPOINT = reqparse.RequestParser()
ENDPOINT.add_argument("token", required=True)
ENDPOINT.add_argument("all", default=False)


class Account(ndb.Model):
    email = ndb.StringProperty()
    name = ndb.StringProperty()
    secret = ndb.StringProperty()
    timestamp = ndb.DateTimeProperty(auto_now_add=True)


class Endpoint(ndb.Model):
    name = ndb.StringProperty()
    url = ndb.StringProperty()
    timestamp = ndb.DateTimeProperty(auto_now_add=True)


class Authorisation(ndb.Model):
    account = ndb.KeyProperty(kind=Account)
    endpoint = ndb.KeyProperty(kind=Endpoint)
    timestamp = ndb.DateTimeProperty(auto_now_add=True)


config = {}


def response(data, cache=0):
    r = make_response(json.dumps(data))
    r.headers["Content-Type"] = "application/json"
    if cache > 0:
        r.headers["Cache-Control"] = "max-age=%s" % cache
    else:
        r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        r.headers["Expires"] = "0"
    return r


def constant_time_compare(val1, val2):
    """
    Borrowed from Django!

    Returns True if the two strings are equal, False otherwise.
    The time taken is independent of the number of characters that match.
    For the sake of simplicity, this function executes in constant time only
    when the two strings have the same length. It short-circuits when they
    have different lengths. Since Django only uses it to compare hashes of
    known expected length, this is acceptable.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0


def datetime_to_epoch(timestamp):
    return int(round((timestamp - EPOCH).total_seconds() * 1000))


def details(account, cache=0):
    authorisations = Authorisation.query(Authorisation.account ==
                                         account.key).iter()
    endpoints = ndb.get_multi([auth.endpoint for auth in authorisations])
    return response(
        {
            "email": account.email,
            "name": account.name,
            "secret": account.secret,
            "timestamp": datetime_to_epoch(account.timestamp),
            "endpoints": [{
                "id": endpoint.key.id(),
                "name": endpoint.name,
                "url": endpoint.url,
                "timestamp": datetime_to_epoch(endpoint.timestamp)
            } for endpoint in endpoints]
        }, cache)


class PingResource(Resource):
    def get(self):
        return "pong"


class InitResource(Resource):
    def put(self):
        endpoint = Endpoint(name="dummy-endpoint",
                            url="https://dummy-endpoint")
        endpoint.put()
        account = Account(name="dummy-account",
                          email="dummy@account",
                          secret=str(uuid.uuid4()))
        account.put()
        Authorisation(account=account.key, endpoint=endpoint.key).put()
        return "", 204


class EndpointResource(Resource):
    def get(self):
        args = ENDPOINT.parse_args()
        if not constant_time_compare(args["token"], config["endpoint"]):
            return "", 403
        else:
            return response([{
                "id": endpoint.key.id(),
                "name": endpoint.name,
                "url": endpoint.url,
                "timestamp": datetime_to_epoch(endpoint.timestamp)
            } for endpoint in Endpoint.query().iter()])

    def put(self):
        if not constant_time_compare(request.form["token"],
                                     config["endpoint"]):
            return "", 403
        else:
            Endpoint(id=request.form["id"],
                     name=request.form[
                         "name"],
                     url=request.form["url"]).put()
            return "", 204


class AuthResource(Resource):
    def get(self):
        args = VERIFY.parse_args()
        account = Account.query(Account.secret == args["secret"]).get()
        return details(account, 60) if account is not None else ("", 403)

    def post(self):
        aaf = jwt.decode(request.form["assertion"],
                         config["aaf"][
                             "secret"],
                         audience=config["aaf"]["audience"],
                         algorithms=["HS256"])
        key = aaf[ATTRIBUTES]["edupersontargetedid"]
        account = Account.get_by_id(key)
        if account is None:
            email = aaf[ATTRIBUTES]["mail"]
            name = aaf[ATTRIBUTES]["displayname"]
            account = Account(id=key,
                              email=email,
                              name=name,
                              secret=str(uuid.uuid4()))
            account.put()
            # Temporary convenience: add auth for eRSA users.
            if email.endswith("@ersa.edu.au"):
                futures = [Authorisation(account=account.key,
                                         endpoint=endpoint.key).put_async()
                           for endpoint in Endpoint.query().iter()]
                ndb.Future.wait_all(futures)
        authorisations = Authorisation.query(Authorisation.account ==
                                             account.key).iter()
        endpoints = ndb.get_multi([auth.endpoint for auth in authorisations])
        endpoints = [{
            "id": endpoint.key.id(),
            "name": endpoint.name,
            "url": endpoint.url,
            "timestamp": datetime_to_epoch(endpoint.timestamp)
        } for endpoint in endpoints]
        html = render_template("auth.html",
                               endpoints=endpoints,
                               email=account.email,
                               secret=account.secret)
        return make_response(html, 200, HTML_HEADERS)
