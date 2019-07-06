#!/usr/bin/env python3

from flask import Flask, request, jsonify, abort, make_response, g
from flask_marshmallow import Marshmallow, Schema
from flask_sqlalchemy import SQLAlchemy
from marshmallow_sqlalchemy import ModelSchema
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as JsonWebToken, BadSignature, SignatureExpired
import os

db = SQLAlchemy()
ma = Marshmallow()

class User(db.Model):
    username = db.Column(db.String(64), primary_key=True, nullable=False)
    authenticationPassword = db.Column(db.String, nullable=False)
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

    def generate_auth_token(self, jsonWebToken):
        return jsonWebToken.dumps({'username': self.username})

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
        databaseFilePath = os.path.join(baseDirectory, 'passbutlerserver.sqlite')
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + databaseFilePath

        app.config.from_envvar('PASSBUTLER_SETTINGS')
    else:
        ## Use `flask_testing.TestCase` fields for configuration
        app.config.from_object(testConfig)

    if not app.config['SECRET_KEY']:
        raise ValueError("The 'SECRET_KEY' is not set in configuration!")

    db.init_app(app)
    ma.init_app(app)

    ## Create database tables if not in unit test mode
    if (testConfig is None):
        with app.app_context():
            db.create_all()











    jsonWebToken = JsonWebToken(app.config['SECRET_KEY'], expires_in=3600)

    passwordAuth = HTTPBasicAuth()
    tokenAuth = HTTPTokenAuth('Bearer')

    @passwordAuth.verify_password
    def verify_password(username, password):
        g.user = None
        requestingUser = User.query.filter_by(username=username).first()

        if requestingUser is not None and check_password_hash(requestingUser.authenticationPassword, password):
            g.user = requestingUser
            return True

        return False

    @tokenAuth.verify_token
    def verify_token(token):
        g.user = None

        try:
            tokenData = jsonWebToken.loads(token)
        except SignatureExpired:
            return False
        except BadSignature:
            return False

        if 'username' in tokenData:
            g.user = User.query.filter_by(username=tokenData['username']).first()
            return True

        return False

    @passwordAuth.error_handler
    @tokenAuth.error_handler
    def unauthorized_httpauth():
        abort(403)























    @app.errorhandler(400)
    def invalid_request(error):
        return make_response(jsonify({'error': 'Invalid request'}), 400)

    @app.errorhandler(403)
    def unauthorized(error):
        return make_response(jsonify({'error': 'Unauthorized'}), 403)

    @app.errorhandler(404)
    def not_found(error):
        return make_response(jsonify({'error': 'Not found'}), 404)

    @app.errorhandler(409)
    def already_exists(error):
        return make_response(jsonify({'error': 'Already exists'}), 409)

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

    @app.route("/token", methods=["GET"])
    @passwordAuth.login_required
    def request_token():
        token = g.user.generate_auth_token(jsonWebToken)
        return jsonify({'token': token.decode('ascii')})

    @app.route("/user/<username>", methods=["GET"])
    @tokenAuth.login_required
    def get_user_detail(username):
        user = User.query.get(username)

        if user is None:
            abort(404)

        result = UserSchema().dump(user)
        return jsonify(result.data)

    return app

if __name__ == '__main__':
    app = create_app()

    ## TODO: Set debug via configuration + general better configuration handling
    app.run(host='127.0.0.1', debug=True)
