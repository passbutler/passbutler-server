#!/usr/bin/env python3

from flask import Flask, request, jsonify, abort, make_response
from flask_marshmallow import Marshmallow, Schema
from flask_sqlalchemy import SQLAlchemy
from marshmallow_sqlalchemy import ModelSchema
import json
import os

db = SQLAlchemy()
ma = Marshmallow()

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
        self.deleted = deleted
        self.modified = modified
        self.created = created

    def __repr__(self):
        return "<User(username={self.username!r})>".format(self=self)

class UserSchema(ModelSchema):
    class Meta:
        model = User

        ## Do not connect schema to SQLAlchemy database session
        transient = True

class PublicUserSchema(Schema):
    class Meta:
        fields = ('username', 'itemEncryptionPublicKey', 'deleted', 'modified', 'created')

def create_app(testConfig=None):
    app = Flask(__name__)

    ## General config (production and test related)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    if (testConfig is None):
        baseDirectory = os.path.abspath(os.path.dirname(__file__))
        databaseFilePath = os.path.join(baseDirectory, 'passbutler.sqlite')
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + databaseFilePath
    else:
        ## Use `flask_testing.TestCase` fields for configuration
        app.config.from_object(testConfig)

    db.init_app(app)
    ma.init_app(app)

    ## Create database tables if not in unit test mode
    if (testConfig is None):
        with app.app_context():
            db.create_all()

    @app.errorhandler(404)
    def not_found(error):
        return make_response(jsonify({'error': 'Not found'}), 404)

    @app.errorhandler(409)
    def already_exists(error):
        return make_response(jsonify({'error': 'Already exists'}), 409)

    @app.errorhandler(400)
    def invalid_request(error):
        return make_response(jsonify({'error': 'Invalid request'}), 400)

    @app.errorhandler(Exception)
    def unhandled_exception(e):
        app.logger.error('Unexpected exception occured: %s', (e))
        return make_response(jsonify({'error': 'Server error'}), 500)

    @app.route("/users", methods=["GET"])
    def get_users():
        allUsers = User.query.all()
        result = PublicUserSchema(many=True).dump(allUsers)
        return jsonify(result.data)

    @app.route("/users", methods=["POST"])
    def create_users():
        usersSchema = UserSchema(many=True).load(request.json)

        if (len(usersSchema.errors) > 0):
            app.logger.debug('Model validation failed with errors: {0}'.format(usersSchema.errors))
            abort(400)

        users = usersSchema.data

        for user in users:
            if User.query.filter_by(username=user.username).first() is None:
                db.session.add(user)
            else:
                app.logger.debug('The user {0} already exists!'.format(user.username))
                abort(409)

        db.session.commit()

        return ('', 204)

    @app.route("/user/<username>", methods=["GET"])
    def get_user_detail(username):
        user = User.query.get(username)

        if user is None:
            abort(404)

        result = UserSchema().dump(user)
        return jsonify(result.data)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='127.0.0.1', debug=True)
