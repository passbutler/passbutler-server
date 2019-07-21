#!/usr/bin/env python3

from flask import Flask, request, jsonify, abort, make_response, g
from flask_marshmallow import Marshmallow, Schema
from flask_sqlalchemy import SQLAlchemy
from marshmallow_sqlalchemy import ModelSchema
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer
import os

db = SQLAlchemy()
ma = Marshmallow()

class User(db.Model):
    username = db.Column(db.String(64), primary_key=True, nullable=False)
    authenticationPasswordHash = db.Column(db.String, nullable=False)
    masterKeyDerivationInformation = db.Column(db.String, nullable=False)
    masterEncryptionKey = db.Column(db.String, nullable=False)
    itemEncryptionPublicKey = db.Column(db.String, nullable=False)
    itemEncryptionSecretKey = db.Column(db.String, nullable=False)
    settings = db.Column(db.String, nullable=False)
    deleted = db.Column(db.Boolean, nullable=False)
    modified = db.Column(db.Integer, nullable=False)
    created = db.Column(db.Integer, nullable=False)

    def __init__(
        self,
        username,
        authenticationPasswordHash,
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
        self.authenticationPasswordHash = authenticationPasswordHash
        self.masterKeyDerivationInformation = masterKeyDerivationInformation
        self.masterEncryptionKey = masterEncryptionKey
        self.itemEncryptionPublicKey = itemEncryptionPublicKey
        self.itemEncryptionSecretKey = itemEncryptionSecretKey
        self.settings = settings
        self.deleted = deleted
        self.modified = modified
        self.created = created

    def __repr__(self):
        return "<User(username={user.username!r}) @ {id!r}>".format(user=self, id=id(self))

    def checkAuthenticationPassword(self, password):
        return check_password_hash(self.authenticationPasswordHash, password)

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
        fields = ('authenticationPasswordHash', 'masterEncryptionKey', 'settings', 'modified')

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

    if not app.config['SECRET_KEY']:
        raise ValueError("The 'SECRET_KEY' is not set in configuration!")

    db.init_app(app)
    ma.init_app(app)

    ## Create database tables if not in unit test mode
    if testConfig is None:
        with app.app_context():
            db.create_all()

    tokenSerializer = TimedJSONWebSignatureSerializer(app.config['SECRET_KEY'], expires_in=3600)

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
            ## If any exception ocures, the token is invalid/expired
            wasSuccessful = False

        return wasSuccessful

    @passwordAuth.error_handler
    @webTokenAuth.error_handler
    def httpAuthUnauthorizedHandler():
        ## Just pass the event to normal Flask handler
        abort(403)

    @app.errorhandler(400)
    def invalidRequestHandler(error):
        return make_response(jsonify({'error': 'Invalid request'}), 400)

    @app.errorhandler(403)
    def unauthorizedRequestHandler(error):
        return make_response(jsonify({'error': 'Unauthorized'}), 403)

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
    @app.route("/token", methods=["GET"])
    @passwordAuth.login_required
    def get_token():
        token = g.authenticatedUser.generateAuthenticationToken(tokenSerializer)
        return jsonify({'token': token})

    @app.route("/users", methods=["GET"])
    def get_users():
        allUsers = User.query.all()
        result = PublicUserSchema(many=True).dump(allUsers)
        return jsonify(result.data)

    @app.route("/users", methods=["POST"])
    def create_users():
        usersSchema = DefaultUserSchema(many=True).load(request.json)

        if len(usersSchema.errors) > 0:
            app.logger.warning('Model validation failed with errors: {0}'.format(usersSchema.errors))
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
    @webTokenAuth.login_required
    def get_user_detail(username):
        ## No record exists check needed because authentication never succeeds than
        user = User.query.get(username)

        ## A user only can see his own details
        if (user.username != g.authenticatedUser.username):
            abort(403)

        result = DefaultUserSchema().dump(user)
        return jsonify(result.data)

    @app.route("/user/<username>", methods=["PUT"])
    @webTokenAuth.login_required
    def update_user_detail(username):
        ## No record exists check needed because authentication never succeeds than
        user = User.query.get(username)

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

    ## TODO: Set debug via configuration + general better configuration handling
    app.run(host='127.0.0.1', debug=True)
