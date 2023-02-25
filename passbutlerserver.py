#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, request, jsonify, abort, make_response
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from flask_marshmallow import Marshmallow, Schema
from flask_sqlalchemy import SQLAlchemy
from jwt.exceptions import InvalidTokenError
from logging import FileHandler
from marshmallow.exceptions import ValidationError
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from sqlalchemy import event, and_
from werkzeug.security import check_password_hash
import datetime
import jwt
import logging

API_VERSION_PREFIX = 'v1'

JWT_SIGNATURE_ALGORITHM = 'HS512'
JWT_EXPIRATION_SECONDS = 3600

db = SQLAlchemy()
ma = Marshmallow()

"""
Models and schemas

"""

class Item(db.Model):

    __tablename__ = 'items'

    id = db.Column(db.String, primary_key=True, nullable=False)
    userId = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
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

class DefaultItemSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Item
        load_instance = True
        include_fk = True
        transient = True

class ItemAuthorization(db.Model):

    __tablename__ = 'item_authorizations'

    id = db.Column(db.String, primary_key=True, nullable=False)
    userId = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
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

class DefaultItemAuthorizationSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = ItemAuthorization
        load_instance = True
        include_fk = True
        transient = True

class User(db.Model):

    __tablename__ = 'users'

    id = db.Column(db.String, primary_key=True, nullable=False)
    username = db.Column(db.String, unique=True, nullable=False)
    fullName = db.Column(db.String, nullable=False)
    serverComputedAuthenticationHash = db.Column(db.String, nullable=False)
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
        id,
        username,
        fullName,
        serverComputedAuthenticationHash,
        masterKeyDerivationInformation,
        masterEncryptionKey,
        itemEncryptionPublicKey,
        itemEncryptionSecretKey,
        settings,
        deleted,
        modified,
        created
    ):
        self.id = id
        self.username = username
        self.fullName = fullName
        self.serverComputedAuthenticationHash = serverComputedAuthenticationHash
        self.masterKeyDerivationInformation = masterKeyDerivationInformation
        self.masterEncryptionKey = masterEncryptionKey
        self.itemEncryptionPublicKey = itemEncryptionPublicKey
        self.itemEncryptionSecretKey = itemEncryptionSecretKey
        self.settings = settings
        self.deleted = deleted
        self.modified = modified
        self.created = created

    def __repr__(self):
        return "<User(id={user.id!r}) @ {objId!r}>".format(user=self, objId=id(self))

    def checkLocalComputedAuthenticationHash(self, localComputedAuthenticationHash):
        return check_password_hash(self.serverComputedAuthenticationHash, localComputedAuthenticationHash)

    def generateAuthenticationToken(
        self,
        secretKey,
        expirationDelta=datetime.timedelta(seconds=JWT_EXPIRATION_SECONDS),
        signatureAlgorithm=JWT_SIGNATURE_ALGORITHM
    ):
        currentDateTimeUTC = datetime.datetime.now(tz=datetime.timezone.utc)

        return jwt.encode(
            payload={
                'id': self.id,
                'iat': currentDateTimeUTC,
                'exp': currentDateTimeUTC + expirationDelta
            },
            key=secretKey,
            algorithm=signatureAlgorithm
        )

class PublicUserSchema(Schema):
    class Meta:
        # Only the following fields are allowed to see for this schema
        fields = ('id', 'username', 'fullName', 'itemEncryptionPublicKey', 'deleted', 'modified', 'created')

class DefaultUserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User
        load_instance = True
        transient = True

"""
App implementation and routes

"""

def createApp(testConfig=None):
    app = Flask(__name__)

    # Signals of SQLAlchemy are not used
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    if testConfig is None:
        app.config.from_envvar('PASSBUTLER_SETTINGS')
    else:
        app.config.from_object(testConfig)

    checkMandatoryConfigurationValues(app)

    secretKey = obtainSecretKey(app)
    registrationInvitationCode = obtainRegistrationInvitationCode(app)

    databaseFilePath = app.config['DATABASE_FILE']
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + databaseFilePath

    initializeLogger(app)

    db.init_app(app)
    ma.init_app(app)

    enableForeignKeyEnforcement(app)

    # Create database tables if not in unit test mode
    if testConfig is None:
        createDatabaseStructure(app)

    passwordAuth = HTTPBasicAuth()
    webTokenAuth = HTTPTokenAuth('Bearer')

    @passwordAuth.verify_password
    def httpAuthVerifyPassword(username, localComputedAuthenticationHash):
        authenticatedUser = None

        # Authentication is only possible for non-deleted users
        requestingUser = db.session.query(User).filter_by(username=username, deleted=False).first()

        if requestingUser is not None and requestingUser.checkLocalComputedAuthenticationHash(localComputedAuthenticationHash):
            authenticatedUser = requestingUser

        return authenticatedUser

    @webTokenAuth.verify_token
    def httpAuthVerifyToken(token):
        authenticatedUser = None

        try:
            tokenData = jwt.decode(
                jwt=token,
                key=secretKey,
                algorithms=[JWT_SIGNATURE_ALGORITHM],
                leeway=datetime.timedelta(seconds=JWT_EXPIRATION_SECONDS),
            )

            userId = tokenData.get('id')

            if userId is not None:
                # Authentication is only possible for non-deleted users
                requestingUser = db.session.query(User).filter_by(id=userId, deleted=False).first()

                if requestingUser is not None:
                    authenticatedUser = requestingUser

        except InvalidTokenError:
            authenticatedUser = None

        return authenticatedUser

    @passwordAuth.error_handler
    @webTokenAuth.error_handler
    def httpAuthUnauthorizedHandler():
        # Just pass the event to normal Flask handler
        abort(401)

    @app.errorhandler(400)
    def invalidRequestHandler(_):
        return make_response(jsonify({'error': 'Invalid request'}), 400)

    @app.errorhandler(401)
    def unauthorizedRequestHandler(_):
        return make_response(jsonify({'error': 'Unauthorized'}), 401)

    @app.errorhandler(403)
    def forbiddenRequestHandler(_):
        return make_response(jsonify({'error': 'Forbidden'}), 403)

    @app.errorhandler(404)
    def notFoundRequestHandler(_):
        return make_response(jsonify({'error': 'Not found'}), 404)

    @app.errorhandler(409)
    def alreadyExistsRequestHandler(_):
        return make_response(jsonify({'error': 'Already exists'}), 409)

    @app.errorhandler(Exception)
    def unhandledExceptionHandler(exception):
        app.logger.error('Unexpected exception occurred: %s', exception)
        return make_response(jsonify({'error': 'Server error'}), 500)

    @app.after_request
    def logRequestResponse(response):
        if app.config.get('ENABLE_REQUEST_LOGGING', False):
            app.logger.info(
                'Response for request %s %s: %s\n' +
                '--------------------------------------------------------------------------------\n' +
                '%s' +
                '--------------------------------------------------------------------------------\n' +
                '%s\n' +
                '--------------------------------------------------------------------------------\n',
                request.method,
                request.path,
                response.status,
                request.headers,
                response.data.decode('utf-8')
            )

        return response

    @app.put('/' + API_VERSION_PREFIX + '/register')
    def registerUser():
        if not app.config.get('REGISTRATION_ENABLED', False):
            app.logger.warning('The user registration is not enabled!')
            abort(403)

        if request.headers.get('Registration-Invitation-Code', None) != registrationInvitationCode:
            app.logger.warning('The registration invitation code is not correct!')
            abort(401)

        try:
            # Do not set database session and instance yet to avoid implicit model modification
            userSchemaResult = DefaultUserSchema().load(request.json, session=None, instance=None)

            username = userSchemaResult.username

            # Be sure, the user does not exists
            if db.session.query(User).filter_by(username=username).first() is not None:
                app.logger.warning(
                    'The user (username="{0}") already exists - registration is not possible!'
                    .format(username)
                )
                abort(409)

            db.session.add(userSchemaResult)
            db.session.commit()

        except ValidationError as e:
            app.logger.warning('Model validation failed with errors: {0}'.format(e))
            abort(400)

        return '', 204

    """
    Get a new token is only possible with password based authentication
    to be sure tokens can't refresh themselves for unlimited time!
    """
    @app.get('/' + API_VERSION_PREFIX + '/token')
    @passwordAuth.login_required
    def getToken():
        authenticatedUser = passwordAuth.current_user()
        token = authenticatedUser.generateAuthenticationToken(secretKey=secretKey)
        return jsonify({'token': token})

    @app.get('/' + API_VERSION_PREFIX + '/users')
    @webTokenAuth.login_required
    def getUsers():
        allUsers = db.session.query(User).all()
        result = PublicUserSchema(many=True).dump(allUsers)
        return jsonify(result)

    @app.get('/' + API_VERSION_PREFIX + '/user')
    @webTokenAuth.login_required
    def getUserDetails():
        authenticatedUser = webTokenAuth.current_user()
        result = DefaultUserSchema().dump(authenticatedUser)
        return jsonify(result)

    @app.put('/' + API_VERSION_PREFIX + '/user')
    @webTokenAuth.login_required
    def setUserDetails():
        authenticatedUser = webTokenAuth.current_user()

        try:
            # Do not set database session and instance yet to avoid implicit model modification
            userSchemaResult = DefaultUserSchema().load(request.json, session=None, instance=None)

            newUsername = userSchemaResult.username

            # Be sure, the user does not exists
            if authenticatedUser.username != newUsername and db.session.query(User).filter_by(username=newUsername).first() is not None:
                app.logger.warning(
                    'The user (username="{0}") already exists - update is not possible!'
                    .format(newUsername)
                )
                abort(409)

            authenticatedUser.username = newUsername
            authenticatedUser.fullName = userSchemaResult.fullName
            authenticatedUser.serverComputedAuthenticationHash = userSchemaResult.serverComputedAuthenticationHash
            authenticatedUser.masterEncryptionKey = userSchemaResult.masterEncryptionKey
            authenticatedUser.settings = userSchemaResult.settings
            authenticatedUser.modified = userSchemaResult.modified

            db.session.commit()

        except ValidationError as e:
            app.logger.warning('Model validation failed with errors: {0}'.format(e))
            abort(400)

        return '', 204

    @app.get('/' + API_VERSION_PREFIX + '/user/items')
    @webTokenAuth.login_required
    def getUserItems():
        authenticatedUser = webTokenAuth.current_user()

        itemAuthorizations = db.session.query(ItemAuthorization).filter_by(userId=authenticatedUser.id).all()
        itemAuthorizationItemIds = map(lambda itemAuthorization: itemAuthorization.itemId, itemAuthorizations)
        userItems = db.session.query(Item).filter(Item.id.in_(itemAuthorizationItemIds))

        deletedItemAuthorizations = filter(lambda itemAuthorization: itemAuthorization.deleted == True, itemAuthorizations)
        deletedItemAuthorizationItemIds = list(map(lambda itemAuthorization: itemAuthorization.itemId, deletedItemAuthorizations))

        for userItem in userItems:
            # If the item has a deleted item authorization manipulate the item contents
            if (userItem.id in deletedItemAuthorizationItemIds):
                # Strip the item data
                userItem.data = None

                # Reset date fields to mark the item record as manipulated
                userItem.modified = 0
                userItem.created = 0

        result = DefaultItemSchema(many=True).dump(userItems)
        return jsonify(result)

    @app.put('/' + API_VERSION_PREFIX + '/user/items')
    @webTokenAuth.login_required
    def setUserItems():
        authenticatedUser = webTokenAuth.current_user()

        try:
            # Do not set database session and instance yet to avoid implicit model modification
            itemsSchemaResult = DefaultItemSchema(many=True).load(request.json, session=None, instance=None)

            for item in itemsSchemaResult:
                createOrUpdateItem(authenticatedUser, item)

            db.session.commit()

        except ValidationError as e:
            app.logger.warning('Model validation failed with errors: {0}'.format(e))
            abort(400)

        return '', 204

    def createOrUpdateItem(authenticatedUser, item):
        # Be sure, the foreign key `userId` exists (check manually for explicit status code and detailed logging)
        if db.session.get(User, item.userId) is None:
            app.logger.warning(
                'The user (id="{0}") of item (id="{1}") does not exist!'
                .format(item.userId, item.id)
            )
            abort(404)

        existingItem = db.session.get(Item, item.id)

        # Determine to create or update the item
        if existingItem is None:
            # It is not allowed to create items for other users
            if item.userId != authenticatedUser.id:
                app.logger.warning(
                    'The requesting user (id={0}) tried to create item for another user (id={1})!'
                    .format(authenticatedUser.id, item.userId)
                )
                abort(403)

            # When an item is created, the item authorization can't be checked because it is still not existing

            db.session.add(item)
        else:
            itemAuthorization = db.session.query(ItemAuthorization).filter_by(userId=authenticatedUser.id, itemId=item.id).first()

            if itemAuthorization is None:
                app.logger.warning(
                    'The requesting user (id={0}) tried to update item (id="{1}") but has no item authorization!'
                    .format(authenticatedUser.id, item.id)
                )
                abort(403)

            if itemAuthorization.readOnly:
                app.logger.warning(
                    'The requesting user (id={0}) tried to update item (id="{1}") but has only a read-only item authorization!'
                    .format(authenticatedUser.id, item.id)
                )
                abort(403)

            if itemAuthorization.deleted:
                app.logger.warning(
                    'The requesting user (id={0}) tried to update item (id="{1}") but has only a deleted item authorization!'
                    .format(authenticatedUser.id, item.id)
                )
                abort(403)

            # Only update the allowed mutable fields
            existingItem.data = item.data
            existingItem.deleted = item.deleted
            existingItem.modified = item.modified

    @app.get('/' + API_VERSION_PREFIX + '/user/itemauthorizations')
    @webTokenAuth.login_required
    def getUserItemAuthorizations():
        authenticatedUser = webTokenAuth.current_user()

        # 1) Item authorizations created for requesting user
        itemAuthorizationsForUser = db.session.query(ItemAuthorization).filter_by(userId=authenticatedUser.id).all()

        # 2) Item authorizations created by requesting user for other users
        userItems = db.session.query(Item).filter_by(userId=authenticatedUser.id).all()
        userItemsIds = map(lambda item: item.id, userItems)
        itemAuthorizationsCreatedByUser = db.session.query(ItemAuthorization).filter(
            and_(
                ItemAuthorization.itemId.in_(userItemsIds),
                ItemAuthorization.userId != authenticatedUser.id
            )
        ).all()

        result = DefaultItemAuthorizationSchema(many=True).dump(
            itemAuthorizationsForUser + itemAuthorizationsCreatedByUser
        )

        return jsonify(result)

    @app.put('/' + API_VERSION_PREFIX + '/user/itemauthorizations')
    @webTokenAuth.login_required
    def setUserItemAuthorizations():
        authenticatedUser = webTokenAuth.current_user()

        try:
            itemAuthorizationsSchema = DefaultItemAuthorizationSchema(many=True)

            # Do not set database session and instance yet to avoid implicit model modification
            itemAuthorizationsSchemaResult = itemAuthorizationsSchema.load(request.json, session=None, instance=None)

            for itemAuthorization in itemAuthorizationsSchemaResult:
                createOrUpdateItemAuthorization(authenticatedUser, itemAuthorization)

            db.session.commit()

        except ValidationError as e:
            app.logger.warning('Model validation failed with errors: {0}'.format(e))
            abort(400)

        return '', 204

    def createOrUpdateItemAuthorization(authenticatedUser, itemAuthorization):
        # Be sure, the foreign key `userId` exists (check manually for explicit status code and detailed logging)
        if db.session.get(User, itemAuthorization.userId) is None:
            app.logger.warning(
                'The user (id="{0}") of item authorization (id="{1}") does not exist!'
                .format(itemAuthorization.userId, itemAuthorization.id)
            )
            abort(404)

        item = db.session.get(Item, itemAuthorization.itemId)

        # Be sure, the foreign key `itemId` exists (check manually for explicit status code and detailed logging)
        if item is None:
            app.logger.warning(
                'The item (id="{0}") of item authorization (id="{1}") does not exist!'
                .format(itemAuthorization.itemId, itemAuthorization.id)
            )
            abort(404)

        # Only the owner of the corresponding item is able to create/update item authorizations
        if item.userId != authenticatedUser.id:
            app.logger.warning(
                'The requesting user (id="{0}") tried to create/update item authorization (id="{1}") for item (id="{2}") that is owned by other user (id={3})!'
                .format(authenticatedUser.id, itemAuthorization.id, item.id, item.userId)
            )
            abort(403)

        existingItemAuthorization = db.session.get(ItemAuthorization, itemAuthorization.id)

        # Determine to create or update the item authorization
        if existingItemAuthorization is None:
            # Check for already existing user+item combination to avoid multiple item authorization for the same user and item
            if db.session.query(ItemAuthorization).filter_by(userId=itemAuthorization.userId, itemId=itemAuthorization.itemId).count() > 0:
                app.logger.warning(
                    'An item authorization already exists for the user (id="{0}") and item (id="{1}")!'
                    .format(itemAuthorization.userId, itemAuthorization.itemId)
                )
                abort(400)

            db.session.add(itemAuthorization)
        else:
            # Only update the allowed mutable fields
            existingItemAuthorization.readOnly = itemAuthorization.readOnly
            existingItemAuthorization.deleted = itemAuthorization.deleted
            existingItemAuthorization.modified = itemAuthorization.modified

    return app

def checkMandatoryConfigurationValues(app):
    mandatoryConfigurationValues = [
        'DATABASE_FILE',
        'LOG_FILE',
        'SECRET_KEY',
        'ENABLE_REQUEST_LOGGING',
        'REGISTRATION_ENABLED',
        'REGISTRATION_INVITATION_CODE',
    ]

    for configurationValue in mandatoryConfigurationValues:
        if configurationValue not in app.config:
            raise ValueError('The value "' + configurationValue + '" is not set in configuration!')

def obtainSecretKey(app):
    configurationSecretKey = app.config.get('SECRET_KEY', None)

    if configurationSecretKey is None or len(configurationSecretKey) < 64:
        raise ValueError('The "SECRET_KEY" in the configuration must be at least 64 characters long!')

    return configurationSecretKey

def obtainRegistrationInvitationCode(app):
    registrationInvitationCode = app.config.get('REGISTRATION_INVITATION_CODE', None)

    if registrationInvitationCode is None or len(registrationInvitationCode) < 16:
        raise ValueError('The "REGISTRATION_INVITATION_CODE" in the configuration must be at least 16 characters long!')

    return registrationInvitationCode

def initializeLogger(app):
    logFilePath = app.config['LOG_FILE']

    if logFilePath is not None:
        fileLogHandler = FileHandler(logFilePath)
        fileLogHandler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s %(name)s [%(threadName)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S.%03d')
        )
        app.logger.addHandler(fileLogHandler)
        app.logger.setLevel(logging.INFO)

    app.logger.info('Pass Butler server is starting')

def enableForeignKeyEnforcement(app):
    # Enables foreign key enforcing which is disabled by default in SQLite
    with app.app_context():
        def enableForeignKeySupport(dbApiConnection, _):
            cursor = dbApiConnection.cursor()
            cursor.execute('PRAGMA foreign_keys=ON;')
            cursor.close()

        event.listen(db.engine, 'connect', enableForeignKeySupport)

def createDatabaseStructure(app):
    with app.app_context():
        db.create_all()
