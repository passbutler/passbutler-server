#!/usr/bin/env python3

from flask import Flask, request, jsonify, abort, make_response, g
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from flask_marshmallow import Marshmallow, Schema
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import TimedJSONWebSignatureSerializer
from marshmallow.exceptions import ValidationError
from marshmallow_sqlalchemy import ModelSchema
from sqlalchemy import event, and_
from werkzeug.security import check_password_hash
import os

API_VERSION_PREFIX = 'v1'

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
        include_fk = True
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
        include_fk = True
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
    with app.app_context():
        def enableForeignKeySupport(dbApiConnection, connectionRecord):
            cursor = dbApiConnection.cursor()
            cursor.execute('PRAGMA foreign_keys=ON;')
            cursor.close()

        event.listen(db.engine, 'connect', enableForeignKeySupport)

    ## Create database tables if not in unit test mode
    if testConfig is None:
        with app.app_context():
            db.create_all()

    tokenSerializer = TimedJSONWebSignatureSerializer(
        app.config['SECRET_KEY'],
        expires_in=3600,
        algorithm_name="HS512"
    )

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

    # @app.after_request
    # def logRequestResponse(response):
    #     app.logger.debug(
    #         'Response for request %s %s: %s\n' +
    #         '--------------------------------------------------------------------------------\n' +
    #         '%s' +
    #         '--------------------------------------------------------------------------------\n' +
    #         '%s\n' +
    #         '--------------------------------------------------------------------------------\n',
    #         request.method,
    #         request.path,
    #         response.status,
    #         request.headers,
    #         response.data.decode('utf-8')
    #     )

    #     return response

    """
    Get a new token is only possible with password based authentication
    to be sure tokens can't refresh themselfs for unlimited time!
    """
    @app.route('/' + API_VERSION_PREFIX + '/token', methods=['GET'])
    @passwordAuth.login_required
    def get_token():
        user = g.authenticatedUser
        token = user.generateAuthenticationToken(tokenSerializer)
        return jsonify({'token': token})

    @app.route('/' + API_VERSION_PREFIX + '/users', methods=['GET'])
    @webTokenAuth.login_required
    def get_users():
        allUsers = User.query.all()
        result = PublicUserSchema(many=True).dump(allUsers)
        return jsonify(result)

    @app.route('/' + API_VERSION_PREFIX + '/users', methods=['PUT'])
    def set_users():
        if (app.config.get('ENABLE_REGISTRATION', False) == False):
            app.logger.warning('The user registration is not enabled!')
            abort(403)

        try:
            ## Do not set database session and instance yet to avoid implicit model modification
            userSchemaResult = DefaultUserSchema().load(request.json, session=None, instance=None)

            username = userSchemaResult.username

            ## Be sure, the user does not exists
            if (User.query.get(username) is not None):
                app.logger.warning(
                    'The user (id="{0}") already exists - registration is not allowed!'.format(username)
                )
                abort(403)

            db.session.add(userSchemaResult)
            db.session.commit()

        except ValidationError as e:
            app.logger.warning('Model validation failed with errors: {0}'.format(e))
            abort(400)

        return ('', 204)

    @app.route('/' + API_VERSION_PREFIX + '/user', methods=['GET'])
    @webTokenAuth.login_required
    def get_user_details():
        user = g.authenticatedUser
        result = DefaultUserSchema().dump(user)
        return jsonify(result)

    @app.route('/' + API_VERSION_PREFIX + '/user', methods=['PUT'])
    @webTokenAuth.login_required
    def set_user_details():
        user = g.authenticatedUser

        try:
            ## Do not set database session and instance yet to avoid implicit model modification
            userSchemaResult = DefaultUserSchema().load(request.json, session=None, instance=None)

            user.masterPasswordAuthenticationHash = userSchemaResult.masterPasswordAuthenticationHash
            user.masterEncryptionKey = userSchemaResult.masterEncryptionKey
            user.settings = userSchemaResult.settings
            user.modified = userSchemaResult.modified

            db.session.commit()

        except ValidationError as e:
            app.logger.warning('Model validation failed with errors: {0}'.format(e))
            abort(400)

        return ('', 204)

    @app.route('/' + API_VERSION_PREFIX + '/user/items', methods=['GET'])
    @webTokenAuth.login_required
    def get_user_items():
        user = g.authenticatedUser

        ## Returns items where the user has a non-deleted item authorization
        itemAuthorizations = ItemAuthorization.query.filter_by(userId=user.username, deleted=False).all()
        itemAuthorizationItemIds = map(lambda itemAuthorization: itemAuthorization.itemId, itemAuthorizations)

        ## No deleted-flag check (the deletion status must be available to user, e.g. to reflect in UI)
        userItems = Item.query.filter(Item.id.in_(itemAuthorizationItemIds))

        result = DefaultItemSchema(many=True).dump(userItems)
        return jsonify(result)

    @app.route('/' + API_VERSION_PREFIX + '/user/items', methods=['PUT'])
    @webTokenAuth.login_required
    def set_user_items():
        user = g.authenticatedUser

        try:
            ## Do not set database session and instance yet to avoid implicit model modification
            itemsSchemaResult = DefaultItemSchema(many=True).load(request.json, session=None, instance=None)

            for item in itemsSchemaResult:
                createOrUpdateItem(user, item)

            db.session.commit()

        except ValidationError as e:
            app.logger.warning('Model validation failed with errors: {0}'.format(e))
            abort(400)

        return ('', 204)

    def createOrUpdateItem(user, item):
        ## No deleted-flag check (not necessary because a deleted-flagged user can't authenticate anyway)
        itemUser = User.query.get(item.userId)

        ## Be sure, the foreign key user exists
        if (itemUser is None):
            app.logger.warning('The user (id="{0}") of item (id="{1}") does not exist!'.format(item.userId, item.id))
            abort(404)

        ## No deleted-flag check (a deleted item must be updatable, e.g. to undo deletion)
        existingItem = Item.query.get(item.id)

        ## Determine to create or update the item
        if (existingItem is None):
            ## It is not allowed to create items for other users
            if (item.userId != user.username):
                app.logger.warning(
                    'The owner user of the item ({0}) is not the requesting user ({1}) - this is not allowed!'
                    .format(item.userId, user.username)
                )
                abort(403)

            db.session.add(item)
        else:
            itemAuthorization = ItemAuthorization.query.filter_by(userId=user.username, itemId=item.id).first()

            if (itemAuthorization is None):
                app.logger.warning(
                    'The user has no item authorization for item (id="{0}") - modification is not allowed!'
                    .format(item.id)
                )
                abort(403)

            if (itemAuthorization.readOnly == True):
                app.logger.warning(
                    'The user has a read-only item authorization for item (id="{0}") - modification is not allowed!'
                    .format(item.id)
                )
                abort(403)

            ## Only update the allowed mutable fields
            existingItem.data = item.data
            existingItem.deleted = item.deleted
            existingItem.modified = item.modified

    @app.route('/' + API_VERSION_PREFIX + '/user/itemauthorizations', methods=['GET'])
    @webTokenAuth.login_required
    def get_user_item_authorizations():
        user = g.authenticatedUser

        """
        1) Item authorization created for current user:
        No deleted-flag check (the deletion status must be available to user, e.g. to avoid try update according item)
        """
        itemAuthorizationsForUser = ItemAuthorization.query.filter_by(userId=user.username).all()

        """
        2) Item authorization created by current user for other users:
        No deleted-flag check (the deletion status must be available to user, e.g. to reflect in UI)
        """
        userItems = Item.query.filter_by(userId=user.username).all()
        userItemsIds = map(lambda item: item.id, userItems)
        itemAuthorizationsCreatedByUser = ItemAuthorization.query.filter(
            and_(
                ItemAuthorization.itemId.in_(userItemsIds),
                ItemAuthorization.userId != user.username
            )
        ).all()

        result = DefaultItemAuthorizationSchema(many=True).dump(
            itemAuthorizationsForUser + itemAuthorizationsCreatedByUser
        )
        return jsonify(result)

    @app.route('/' + API_VERSION_PREFIX + '/user/itemauthorizations', methods=['PUT'])
    @webTokenAuth.login_required
    def set_user_item_authorizations():
        user = g.authenticatedUser

        try:
            itemAuthorizationsSchema = DefaultItemAuthorizationSchema(many=True)

            ## Do not set database session and instance yet to avoid implicit model modification
            itemAuthorizationsSchemaResult = itemAuthorizationsSchema.load(request.json, session=None, instance=None)

            for itemAuthorization in itemAuthorizationsSchemaResult:
                createOrUpdateItemAuthorization(user, itemAuthorization)

            db.session.commit()

        except ValidationError as e:
            app.logger.warning('Model validation failed with errors: {0}'.format(e))
            abort(400)

        return ('', 204)

    def createOrUpdateItemAuthorization(user, itemAuthorization):
        ## No deleted-flag check (not necessary because a deleted-flagged user can't authenticate anyway)
        itemAuthorizationUser = User.query.get(itemAuthorization.userId)

        ## Be sure, the foreign key user exists
        if (itemAuthorizationUser is None):
            app.logger.warning(
                'The user (id="{0}") of item authorization (id="{1}") does not exist!'
                .format(itemAuthorization.userId, itemAuthorization.id)
            )
            abort(404)

        """
        No deleted-flag check
        (item authorizations of a deleted item must be updatable, e.g. to later revoke access of users)
        """
        itemAuthorizationItem = Item.query.get(itemAuthorization.itemId)

        ## Be sure, the foreign key user exists
        if (itemAuthorizationItem is None):
            app.logger.warning(
                'The item (id="{0}") of item authorization (id="{1}") does not exist!'
                .format(itemAuthorization.itemId, itemAuthorization.id)
            )
            abort(404)

        ## Only the owner of the corresponding item is able to create/update item
        if (itemAuthorizationItem.userId != user.username):
            app.logger.warning(
                'The item (id="{0}") of item authorization (id="{1}") is not owned by requesting user "{2}"!'
                .format(itemAuthorization.itemId, itemAuthorization.id, user)
            )
            abort(403)

        ## No deleted-flag check (a deleted item authorization must be updatable, e.g. to undo deletion)
        existingItemAuthorization = ItemAuthorization.query.get(itemAuthorization.id)

        ## Determine to create or update the item authorization
        if (existingItemAuthorization is None):
            """
            If the item authorization is not existing, check if any is already existing for user+item combination
            to avoid multiple item authorization for the same user and item:
            """
            if (ItemAuthorization.query.filter_by(userId=user.username, itemId=itemAuthorization.itemId).count() > 0):
                app.logger.warning(
                    'An item authorization already exists for the item (id="{0}") and requesting user (id="{1}") ' + 
                    '- do not created another one!'
                    .format(itemAuthorization.itemId, user.username)
                )
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

