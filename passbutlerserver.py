#!/usr/bin/env python3

from flask import Flask, request, jsonify, abort, make_response, g
from flask_marshmallow import Marshmallow, Schema
from flask_sqlalchemy import SQLAlchemy
from marshmallow_sqlalchemy import ModelSchema
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from werkzeug.security import check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer
import os

db = SQLAlchemy()
ma = Marshmallow()

## TODO: Check difference between `User.query.filter_by(username=username)` and `User.query.get(username)`

class User(db.Model):

    __tablename__ = 'users'

    username = db.Column(db.String(64), primary_key=True, nullable=False)
    masterPasswordAuthenticationHash = db.Column(db.String, nullable=False)
    masterKeyDerivationInformation = db.Column(db.JSON, nullable=False)
    masterEncryptionKey = db.Column(db.JSON, nullable=False)
    itemEncryptionPublicKey = db.Column(db.JSON, nullable=False)
    itemEncryptionSecretKey = db.Column(db.JSON, nullable=False)
    settings = db.Column(db.JSON, nullable=False)
    deleted = db.Column(db.Boolean, nullable=False)
    modified = db.Column(db.Integer, nullable=False)
    created = db.Column(db.Integer, nullable=False)

    def __init__(
        self,
        username,
        masterPasswordAuthenticationHash,
        masterKeyDerivationInformation,
        masterEncryptionKey,
        itemEncryptionPublicKey,
        itemEncryptionSecretKey,
        settings,
        deleted,
        modified,
        created
    ):
        self.username = username
        self.masterPasswordAuthenticationHash = masterPasswordAuthenticationHash
        self.masterKeyDerivationInformation = masterKeyDerivationInformation
        self.masterEncryptionKey = masterEncryptionKey
        self.itemEncryptionPublicKey = itemEncryptionPublicKey
        self.itemEncryptionSecretKey = itemEncryptionSecretKey
        self.settings = settings
        self.deleted = deleted
        self.modified = modified
        self.created = created

    def __repr__(self):
        return "<User(username={user.username!r}) @ {objId!r}>".format(user=self, objId=id(self))

    def checkAuthenticationPassword(self, password):
        return check_password_hash(self.masterPasswordAuthenticationHash, password)

    def generateAuthenticationToken(self, tokenSerializer):
        return tokenSerializer.dumps({'username': self.username}).decode('ascii')

class PublicUserSchema(Schema):
    class Meta:
        fields = ('username', 'itemEncryptionPublicKey', 'deleted', 'modified', 'created')

class DefaultUserSchema(ModelSchema):
    class Meta:
        model = User

        ## Do not implicitly connect schema to SQLAlchemy database session
        transient = True

class UpdateUserSchema(ModelSchema):
    class Meta:
        model = User

        ## Only the following fields are allowed to update
        fields = ('masterPasswordAuthenticationHash', 'masterEncryptionKey', 'settings', 'modified')

        ## Do not implicitly connect schema to SQLAlchemy database session
        transient = True

def createApp(testConfig=None):
    app = Flask(__name__)

    ## General config (production and test related)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    if testConfig is None:
        baseDirectory = os.path.abspath(os.path.dirname(__file__))
        databaseFilePath = os.path.join(baseDirectory, 'passbutlerserver.sqlite')
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + databaseFilePath

        app.config.from_envvar('PASSBUTLER_SETTINGS')
    else:
        ## Use `flask_testing.TestCase` fields for configuration
        app.config.from_object(testConfig)

    mandatoryConfigurationValues = [
        'SERVER_HOST',
        'SERVER_PORT',
        'SECRET_KEY',
    ]

    for configurationValue in mandatoryConfigurationValues:
        if configurationValue not in app.config:
            raise ValueError('The value "' + configurationValue + '" is not set in configuration!')

    db.init_app(app)
    ma.init_app(app)

    ## Create database tables if not in unit test mode
    if testConfig is None:
        with app.app_context():
            db.create_all()

    tokenSerializer = TimedJSONWebSignatureSerializer(app.config['SECRET_KEY'], expires_in=3600, algorithm_name="HS512")

    passwordAuth = HTTPBasicAuth()
    webTokenAuth = HTTPTokenAuth('Bearer')

    @passwordAuth.verify_password
    def httpAuthVerifyPassword(username, password):
        wasSuccessful = False
        g.authenticatedUser = None

        requestingUser = User.query.filter_by(username=username).first()

        if requestingUser is not None and requestingUser.checkAuthenticationPassword(password):
            g.authenticatedUser = requestingUser
            wasSuccessful = True

        return wasSuccessful

    @webTokenAuth.verify_token
    def httpAuthVerifyToken(token):
        wasSuccessful = False
        g.authenticatedUser = None

        try:
            tokenData = tokenSerializer.loads(token)
            username = tokenData.get('username')

            if username is not None:
                user = User.query.filter_by(username=username).first()

                if user is not None:
                    g.authenticatedUser = user
                    wasSuccessful = True
        except:
            ## If any exception occurs, the token is invalid/expired
            wasSuccessful = False

        return wasSuccessful

    @passwordAuth.error_handler
    @webTokenAuth.error_handler
    def httpAuthUnauthorizedHandler():
        ## Just pass the event to normal Flask handler
        abort(401)

    @app.errorhandler(400)
    def invalidRequestHandler(error):
        return make_response(jsonify({'error': 'Invalid request'}), 400)

    @app.errorhandler(401)
    def unauthorizedRequestHandler(error):
        return make_response(jsonify({'error': 'Unauthorized'}), 401)

    @app.errorhandler(403)
    def forbiddenRequestHandler(error):
        return make_response(jsonify({'error': 'Forbidden'}), 403)

    @app.errorhandler(404)
    def notFoundRequestHandler(error):
        return make_response(jsonify({'error': 'Not found'}), 404)

    @app.errorhandler(409)
    def alreadyExistsRequestHandler(error):
        return make_response(jsonify({'error': 'Already exists'}), 409)

    @app.errorhandler(Exception)
    def unhandledExceptionHandler(exception):
        app.logger.error('Unexpected exception occured: %s', (exception))
        return make_response(jsonify({'error': 'Server error'}), 500)

    """
    Get a new token is only possible with password based authentication to be sure
    tokens can't refresh themselfs for unlimited time.

    """
    @app.route('/token', methods=['GET'])
    @passwordAuth.login_required
    def get_token():
        token = g.authenticatedUser.generateAuthenticationToken(tokenSerializer)
        return jsonify({'token': token})

    @app.route('/users', methods=['GET'])
    @webTokenAuth.login_required
    def get_users():
        allUsers = User.query.all()
        result = PublicUserSchema(many=True).dump(allUsers)
        return jsonify(result.data)

    @app.route('/user/<username>', methods=['GET'])
    @webTokenAuth.login_required
    def get_user_details(username):
        user = User.query.get(username)

        ## Record exists check is needed because an authenticated user could request a non-existing record
        if user is None:
            abort(404)

        ## A user only can see his own details
        if (user.username != g.authenticatedUser.username):
            abort(403)

        result = DefaultUserSchema().dump(user)
        return jsonify(result.data)

    @app.route('/user/<username>', methods=['PUT'])
    @webTokenAuth.login_required
    def set_user_details(username):
        user = User.query.get(username)

        ## Record exists check is needed because an authenticated user could request a non-existing record
        if user is None:
            abort(404)

        ## A user only can update his own details
        if (user.username != g.authenticatedUser.username):
            abort(403)

        userSchema = UpdateUserSchema().load(request.json, session=db.session, instance=user, partial=True)

        if len(userSchema.errors) > 0:
            app.logger.warning('Model validation failed with errors: {0}'.format(userSchema.errors))
            abort(400)

        return ('', 204)

    return app

if __name__ == '__main__':
    app = createApp()
    app.run(host=app.config['SERVER_HOST'], port=app.config['SERVER_PORT'])
