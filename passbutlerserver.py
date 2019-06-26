#!/usr/bin/env python3

from flask import Flask, request, jsonify, abort, make_response
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
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






## TODO: only validate partial fields in some requests
## TODO: validate relations?

class UserSchema(ma.ModelSchema):
    class Meta:
        model = User

class PublicUserSchema(ma.Schema):
    class Meta:
        fields = ('username', 'itemEncryptionPublicKey', 'deleted', 'modified', 'created')














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
        ## TODO: Where pass `session` and `transient`?
        unmarshalResult = UserSchema(many=True).load(request.json, session=db.session, transient=True)

        if (len(unmarshalResult.errors) > 0):
            app.logger.debug('Model validation failed with errors: {0}'.format(unmarshalResult.errors))
            abort(400)

        users = unmarshalResult.data

        for user in users:
            if User.query.filter_by(username=user.username).first() is None:
                db.session.add(user)
            else:
                app.logger.debug('The user {0} already exists!'.format(user.username))
                abort(409)

        db.session.commit()

        return ('', 204)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='127.0.0.1', debug=True)
