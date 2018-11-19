#!/usr/bin/env python

from flask import Flask
import flask_restful

import yaml

import api

app = Flask(__name__)
restapi = flask_restful.Api(app)

def add(target, endpoint):
    restapi.add_resource(target, endpoint)

api.config = yaml.load(open("conf.yaml", "r"))

add(api.PingResource, "/ping")
add(api.InitResource, "/init")
add(api.AuthResource, "/auth")
add(api.EndpointResource, "/endpoint")
