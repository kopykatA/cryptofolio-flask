import os

from setup import basedir


class BaseConfig(object):
    SECRET_KEY = 'This is secret'
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:////Users/zy/Desktop/Files/projects/flaskapp/database.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = True
