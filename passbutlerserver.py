#!/usr/bin/env python3

from flask import Flask, request, jsonify, abort, make_response
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.schema import CreateSchema
import json
import os
import time

db = SQLAlchemy()
ma = Marshmallow()

def create_app(test_config=None):
    app = Flask(__name__)

    ## General config (production and test related)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    if (test_config is None):
        baseDirectory = os.path.abspath(os.path.dirname(__file__))
        databaseFilePath = os.path.join(baseDirectory, 'passbutler.sqlite')
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + databaseFilePath
    else:
        ## Use `flask_testing.TestCase` fields for configuration
        app.config.from_object(test_config)

    db.init_app(app)
    ma.init_app(app)

    @app.errorhandler(404)
    def not_found(error):
        return make_response(jsonify({'error': 'Not found'}), 404)

    @app.route("/users", methods=["GET"])
    def get_users():
        allUsers = User.query.all()
        result = usersSchema.dump(allUsers)
        return jsonify(result.data)

    return app

class User(db.Model):
    username = db.Column(db.String(64), primary_key=True, nullable=False)
    masterKeyDerivationInformation = db.Column(db.String, nullable=False)
    masterEncryptionKey = db.Column(db.String, nullable=False)
    itemEncryptionPublicKey = db.Column(db.String, nullable=False)
    itemEncryptionSecretKey = db.Column(db.String, nullable=False)
    settings = db.Column(db.String, nullable=False)
    deleted = db.Column(db.Boolean, nullable=False)
    modified = db.Column(db.Integer, nullable=False)
    created = db.Column(db.Integer, nullable=False)

    def __init__(self, username, masterKeyDerivationInformation, masterEncryptionKey, itemEncryptionPublicKey, itemEncryptionSecretKey, settings, deleted, modified, created):
        self.username = username
        self.masterKeyDerivationInformation = masterKeyDerivationInformation
        self.masterEncryptionKey = masterEncryptionKey
        self.itemEncryptionPublicKey = itemEncryptionPublicKey
        self.itemEncryptionSecretKey = itemEncryptionSecretKey
        self.settings = settings
        self.deleted = False
        self.modified = modified
        self.created = created

class UserSchema(ma.Schema):
    class Meta:
        fields = ('username', 'itemEncryptionPublicKey', 'deleted', 'modified', 'created')

userSchema = UserSchema()
usersSchema = UserSchema(many=True)






# @app.route("/users", methods=["POST"])
# def create_users():

#     if (not request.json or not len(request.json) > 0):
#         abort(400)

#     users = request.json

#     ## TODO: Check if user already exists?
#     for user in users:
#         newUser = User(
#             user['username'],
#             user['masterKeyDerivationInformation'],
#             user['masterEncryptionKey'],
#             user['itemEncryptionPublicKey'],
#             user['itemEncryptionSecretKey'],
#             user['settings'],
#             user['deleted'],
#             user['modified'],
#             user['created']
#         )

#         db.session.add(newUser)

#     db.session.commit()

#     return ('', 204)

# @app.route("/users", methods=["PUT"])
# def update_users():

#     if (not request.json or not len(request.json) > 0):
#         abort(400)

#     users = request.json

#     for user in users:
#         updatedUser = User.query.get(user['username'])

#         if (updatedUser is None):
#             abort(404)

#         ## Update only allowed fields
#         updatedUser.lockTimeout = user['lockTimeout']
#         updatedUser.modified = user['modified']
#         updatedUser.deleted = user['deleted']

#     db.session.commit()

#     return ('', 204)

# @app.route("/user/<username>", methods=["GET"])
# def user_detail(username):
#     user = User.query.get(username)
#     return userSchema.jsonify(user)

# ## TODO: Check only the user itself is allowed to call this route
# @app.route("/user/<username>", methods=["PUT"])
# def user_update(username):
#     user = User.query.get(username)

#     user.lockTimeout = request.json['lockTimeout']
#     user.deleted = request.json['deleted']
#     user.modified = request.json['modified']

#     db.session.commit()
#     return userSchema.jsonify(user)



if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', debug=True)
