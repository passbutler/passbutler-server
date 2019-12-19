#!/usr/bin/env python3

from flask import Flask, request, jsonify, abort, make_response, g
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from flask_marshmallow import Marshmallow, Schema
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import TimedJSONWebSignatureSerializer
from marshmallow_sqlalchemy import ModelSchema
from sqlalchemy import event, and_
from werkzeug.security import check_password_hash
import os

db = SQLAlchemy()
ma = Marshmallow()

"""
Models and schemas

"""

class Item(db.Model):

    __tablename__ = 'items'

    id = db.Column(db.String(36), primary_key=True, nullable=False)
    userId = db.Column(db.String, db.ForeignKey('users.username'), nullable=False)
    data = db.Column(db.JSON, nullable=False)
    deleted = db.Column(db.Boolean, nullable=False)
    modified = db.Column(db.Integer, nullable=False)
    created = db.Column(db.Integer, nullable=False)

    def __init__(
        self,
        id,
        userId,
        data,
        deleted,
        modified,
        created
    ):
        self.id = id
        self.userId = userId
        self.data = data
        self.deleted = deleted
        self.modified = modified
        self.created = created

    def __repr__(self):
        return "<Item(id={item.id!r}) @ {objId!r}>".format(item=self, objId=id(self))

class DefaultItemSchema(ModelSchema):
    class Meta:
        model = Item

        ## Also include foreign keys for this schema
        include_fk = True

        ## Do not connect schema to SQLAlchemy database session to avoid models are implicitly changed when loading data
        transient = True

class ItemAuthorization(db.Model):

    __tablename__ = 'item_authorizations'

    id = db.Column(db.String(36), primary_key=True, nullable=False)
    userId = db.Column(db.String, db.ForeignKey('users.username'), nullable=False)
    itemId = db.Column(db.String, db.ForeignKey('items.id'), nullable=False)
    itemKey = db.Column(db.JSON, nullable=False)
    readOnly = db.Column(db.Boolean, nullable=False)
    deleted = db.Column(db.Boolean, nullable=False)
    modified = db.Column(db.Integer, nullable=False)
    created = db.Column(db.Integer, nullable=False)

    def __init__(
        self,
        id,
        userId,
        itemId,
        itemKey,
        readOnly,
        deleted,
        modified,
        created
    ):
        self.id = id
        self.userId = userId
        self.itemId = itemId
        self.itemKey = itemKey
        self.readOnly = readOnly
        self.deleted = deleted
        self.modified = modified
        self.created = created

    def __repr__(self):
        return "<ItemAuthorization(id={item.id!r}) @ {objId!r}>".format(item=self, objId=id(self))

class DefaultItemAuthorizationSchema(ModelSchema):
    class Meta:
        model = ItemAuthorization

        ## Also include foreign keys for this schema
        include_fk = True

        ## Do not connect schema to SQLAlchemy database session to avoid models are implicitly changed when loading data
        transient = True

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
        ## Only the following fields are allowed to see for this schema
        fields = ('username', 'itemEncryptionPublicKey', 'deleted', 'modified', 'created')

class DefaultUserSchema(ModelSchema):
    class Meta:
        model = User

        ## Do not connect schema to SQLAlchemy database session to avoid models are implicitly changed when loading data
        transient = True

"""
App implementation and routes

"""

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

    ## Enables foreign key enforcing which is disabled by default in SQLite
    if 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI']:
        def _fk_pragma_on_connect(dbapi_con, con_record):
            dbapi_con.execute('pragma foreign_keys=ON')

        with app.app_context():
            event.listen(db.engine, 'connect', _fk_pragma_on_connect)

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

        requestingUser = User.query.filter_by(username=username, deleted=False).first()

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
                user = User.query.filter_by(username=username, deleted=False).first()

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

    ## Get a new token is only possible with password based authentication to be sure tokens can't refresh themselfs for unlimited time!
    @app.route('/token', methods=['GET'])
    @passwordAuth.login_required
    def get_token():
        user = g.authenticatedUser
        token = user.generateAuthenticationToken(tokenSerializer)
        return jsonify({'token': token})

    @app.route('/users', methods=['GET'])
    @webTokenAuth.login_required
    def get_users():
        allUsers = User.query.all()
        result = PublicUserSchema(many=True).dump(allUsers)
        return jsonify(result.data)

    @app.route('/userdetails', methods=['GET'])
    @webTokenAuth.login_required
    def get_user_details():
        user = g.authenticatedUser
        result = DefaultUserSchema().dump(user)
        return jsonify(result.data)

    @app.route('/userdetails', methods=['PUT'])
    @webTokenAuth.login_required
    def set_user_details():
        user = g.authenticatedUser

        ## Do not set database session and instance yet to avoid implicit model modification
        updateUserSchema = DefaultUserSchema().load(request.json, session=None, instance=None)

        if len(updateUserSchema.errors) > 0:
            app.logger.warning('Model validation failed with errors: {0}'.format(updateUserSchema.errors))
            abort(400)

        updatedUser = updateUserSchema.data

        user.masterPasswordAuthenticationHash = updatedUser.masterPasswordAuthenticationHash
        user.masterEncryptionKey = updatedUser.masterEncryptionKey
        user.settings = updatedUser.settings
        user.modified = updatedUser.modified

        db.session.commit()

        return ('', 204)

    @app.route('/items', methods=['GET'])
    @webTokenAuth.login_required
    def get_user_items():
        user = g.authenticatedUser

        ## Returns items where the user has a non-deleted item authorization
        itemAuthorizations = ItemAuthorization.query.filter_by(userId=user.username, deleted=False).all()
        itemAuthorizationItemIds = map(lambda itemAuthorization: itemAuthorization.itemId, itemAuthorizations)

        ## Do not check deleted-flag of the items (the information of deletion must be available to user, e.g. to reflect in UI)
        userItems = Item.query.filter(Item.id.in_(itemAuthorizationItemIds))

        result = DefaultItemSchema(many=True).dump(userItems)
        return jsonify(result.data)

    @app.route('/itemauthorizations', methods=['GET'])
    @webTokenAuth.login_required
    def get_user_item_authorizations():
        user = g.authenticatedUser

        ## Item authorization created for current user: do not check deleted-flag (the information of deletion must be available to user, e.g. to avoid try update according items)
        itemAuthorizationsForUser = ItemAuthorization.query.filter_by(userId=user.username).all()

        ## Item authorization created by current user for other users: do not check deleted-flag (the information of deletion must be available to user, e.g. to reflect in UI)
        userItems = Item.query.filter_by(userId=user.username).all()
        userItemsIds = map(lambda item: item.id, userItems)
        itemAuthorizationsCreatedByUser = ItemAuthorization.query.filter(and_(ItemAuthorization.itemId.in_(userItemsIds), ItemAuthorization.userId != user.username)).all()

        result = DefaultItemAuthorizationSchema(many=True).dump(itemAuthorizationsForUser + itemAuthorizationsCreatedByUser)
        return jsonify(result.data)

    @app.route('/itemauthorizations', methods=['PUT'])
    @webTokenAuth.login_required
    def set_user_item_authorizations():
        user = g.authenticatedUser

        ## Do not set database session and instance yet to avoid implicit model modification
        itemAuthorizationsSchema = DefaultItemAuthorizationSchema(many=True)
        itemAuthorizationsSchemaResult = itemAuthorizationsSchema.load(request.json, session=None, instance=None)

        if len(itemAuthorizationsSchemaResult.errors) > 0:
            app.logger.warning('Model validation failed with errors: {0}'.format(itemAuthorizationsSchemaResult.errors))
            abort(400)

        for itemAuthorization in itemAuthorizationsSchemaResult.data:
            createOrUpdateItemAuthorization(user, itemAuthorization)

        db.session.commit()

        return ('', 204)

    def createOrUpdateItemAuthorization(user, itemAuthorization):
        itemAuthorizationUser = User.query.get(itemAuthorization.userId)

        ## Be sure, the foreign key user exists: do not check deleted-flag of the user (not necessary because a deleted-flagged user can't authenticate anyway)
        if (itemAuthorizationUser is None):
            app.logger.warning('The user (id="{0}") of item authorization (id="{1}") does not exist!'.format(itemAuthorization.userId, itemAuthorization.id))
            abort(404)

        itemAuthorizationItem = Item.query.get(itemAuthorization.itemId)

        ## Be sure, the foreign key item exists: do not check deleted-flag of the item (item authorizations of a deleted item must be updatable, e.g. to later revoke access of users)
        if (itemAuthorizationItem is None):
            app.logger.warning('The item (id="{0}") of item authorization (id="{1}") does not exist!'.format(itemAuthorization.itemId, itemAuthorization.id))
            abort(404)

        ## Only the owner of the corresponding item is able to create/update item
        if (itemAuthorizationItem.userId != user.username):
            app.logger.warning('The item (id="{0}") of item authorization (id="{1}") is not owned by requesting user "{2}"!'.format(itemAuthorization.itemId, itemAuthorization.id, user))
            abort(403)

        ## Determine to create or update the item authorization: do not check deleted-flag of the item authorization (a deleted item authorization must be updatable, e.g. to revert deletion)
        existingItemAuthorization = ItemAuthorization.query.get(itemAuthorization.id)

        if (existingItemAuthorization is None):
            ## If the item authorization is not existing, check if any is already existing for user+item combination to avoid multiple item authorization for the same user and item
            if (ItemAuthorization.query.filter_by(userId=user.username, itemId=itemAuthorization.itemId).count() > 0):
                app.logger.warning('An item authorization already exists for the item (id="{0}") and requesting user (id="{1}") - do not created another one!'.format(itemAuthorization.itemId, user.username))
                abort(400)

            db.session.add(itemAuthorization)
        else:
            ## Only update the allowed mutable fields
            existingItemAuthorization.readOnly = itemAuthorization.readOnly
            existingItemAuthorization.deleted = itemAuthorization.deleted
            existingItemAuthorization.modified = itemAuthorization.modified

    return app

if __name__ == '__main__':
    app = createApp()
    app.run(host=app.config['SERVER_HOST'], port=app.config['SERVER_PORT'])
