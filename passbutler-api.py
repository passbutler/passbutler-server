#!/usr/bin/env python3

from flask import Flask, request, jsonify, abort, make_response
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.schema import CreateSchema
import json
import os
import time

app = Flask(__name__)
baseDirectory = os.path.abspath(os.path.dirname(__file__))
databasePath = os.path.join(baseDirectory, 'passbutler.sqlite')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + databasePath
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)

def createJavaDateTimestamp():
    return int(time.time() * 1000)

class User(db.Model):
    username = db.Column(db.String(80), primary_key=True)
    lockTimeout = db.Column(db.Integer)
    deleted = db.Column(db.Boolean)
    modified = db.Column(db.Integer)
    created = db.Column(db.Integer)

    def __init__(self, username, lockTimeout):
        self.username = username
        self.lockTimeout = lockTimeout
        self.deleted = False

        currentTimestamp = createJavaDateTimestamp()
        self.modified = currentTimestamp
        self.created = currentTimestamp

class UserSchema(ma.Schema):
    class Meta:
        fields = ('username', 'lockTimeout', 'deleted', 'modified', 'created')

userSchema = UserSchema()
usersSchema = UserSchema(many=True)

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

@app.route("/users", methods=["GET"])
def get_users():
    allUsers = User.query.all()
    result = usersSchema.dump(allUsers)
    return jsonify(result.data)

@app.route("/users", methods=["POST"])
def add_users():

    if (not request.json or not len(request.json) > 0):
        abort(400)

    users = request.json

    for user in users:
        addedUser = User(user['username'], user['lockTimeout'])
        db.session.add(addedUser)

    db.session.commit()

    return ('', 204)

@app.route("/users", methods=["PUT"])
def update_users():

    if (not request.json or not len(request.json) > 0):
        abort(400)

    users = request.json

    for user in users:
        updatedUser = User.query.get(user['username'])

        if (updatedUser is None):
            abort(404)

        ## Update only allowed fields
        updatedUser.lockTimeout = user['lockTimeout']
        updatedUser.modified = user['modified']

    db.session.commit()

    return ('', 204)

@app.route("/user/<username>", methods=["GET"])
def user_detail(username):
    user = User.query.get(username)
    return userSchema.jsonify(user)

## TODO: Check only the user itself is allowed to call this route
@app.route("/user/<username>", methods=["PUT"])
def user_update(username):
    user = User.query.get(username)

    user.lockTimeout = request.json['lockTimeout']
    user.deleted = request.json['deleted']
    user.modified = request.json['modified']

    db.session.commit()
    return userSchema.jsonify(user)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
