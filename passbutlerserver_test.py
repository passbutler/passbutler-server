#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask_testing import TestCase
from passbutlerserver import API_VERSION_PREFIX, createApp, db
from passbutlerserver import User, Item, ItemAuthorization
from itsdangerous import TimedJSONWebSignatureSerializer
import base64

"""
Model to JSON functions

"""

def createUserJson(user):
    return {
        'id': user.id,
        'username': user.username,
        'fullName': user.fullName,
        'serverComputedAuthenticationHash': user.serverComputedAuthenticationHash,
        'masterKeyDerivationInformation': user.masterKeyDerivationInformation,
        'masterEncryptionKey': user.masterEncryptionKey,
        'itemEncryptionPublicKey': user.itemEncryptionPublicKey,
        'itemEncryptionSecretKey': user.itemEncryptionSecretKey,
        'settings': user.settings,
        'deleted': user.deleted,
        'modified': user.modified,
        'created': user.created
    }

def createItemJson(item):
    return {
        'id': item.id,
        'userId': item.userId,
        'data': item.data,
        'deleted': item.deleted,
        'modified': item.modified,
        'created': item.created
    }

def createItemAuthorizationJson(itemAuthorization):
    return {
        'id': itemAuthorization.id,
        'userId': itemAuthorization.userId,
        'itemId': itemAuthorization.itemId,
        'itemKey': itemAuthorization.itemKey,
        'readOnly': itemAuthorization.readOnly,
        'deleted': itemAuthorization.deleted,
        'modified': itemAuthorization.modified,
        'created': itemAuthorization.created
    }

"""
Model list sorting functions

"""

def sortUserList(userList):
    return sorted(userList, key=lambda k: k['id'])

def sortItemList(itemList):
    return sorted(itemList, key=lambda k: k['id'])

def sortItemAuthorizationList(itemAuthorizationList):
    return sorted(itemAuthorizationList, key=lambda k: k['id'])

"""
Authentication helpers

"""

def createRegistrationInvitationCodeHttpHeader(invitationCode):
    return {'Registration-Invitation-Code': invitationCode}

def createHttpBasicAuthHeaders(username, password):
    credentialBytes = (username + ':' + password).encode()
    base64EncodedCredentials = base64.b64encode(credentialBytes).decode('utf-8')
    return {'Authorization': 'Basic ' + base64EncodedCredentials}

def createHttpTokenAuthHeaders(secretKey, user, expiresIn=3600, signatureAlgorithm='HS512'):
    tokenSerializer = TimedJSONWebSignatureSerializer(secretKey, expires_in=expiresIn, algorithm_name=signatureAlgorithm)
    token = user.generateAuthenticationToken(tokenSerializer)
    return {'Authorization': 'Bearer ' + token}

"""
Actual test cases

"""

class TestConfigurationTestCase(TestCase):

    TESTING = True

    DATABASE_FILE = ':memory:'
    LOG_FILE = None
    SECRET_KEY = 'This is the secret key for testing - it must be at least 64 characters long'

    ENABLE_REQUEST_LOGGING = False

    REGISTRATION_ENABLED = False
    REGISTRATION_INVITATION_CODE = 'AAAA-BBBB-CCCC-DDDD'

    def create_app(self):
        app = createApp(self)
        return app

    def setUp(self):
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

class PassButlerTestCase(TestConfigurationTestCase):

    @staticmethod
    def addUsers(*users):
        for user in users:
            db.session.add(user)

        db.session.commit()

    @staticmethod
    def addItems(*items):
        for item in items:
            db.session.add(item)

        db.session.commit()

    @staticmethod
    def addItemAuthorizations(*itemAuthorizations):
        for itemAuthorization in itemAuthorizations:
            db.session.add(itemAuthorization)

        db.session.commit()

    """
    Tests for PUT /register

    """

    def test_register_user_non_existing_user(self):
        # Enable registration in config
        self.app.config['REGISTRATION_ENABLED'] = True

        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        response = self.client.put('/' + API_VERSION_PREFIX + '/register', json=requestData, headers=createRegistrationInvitationCodeHttpHeader('AAAA-BBBB-CCCC-DDDD'))

        # Discard uncommitted changes to check if the changes has been committed
        db.session.rollback()

        assert response.status_code == 204
        assert createUserJson(User.query.get('alice-id')) == requestData

    def test_register_user_disabled_registration(self):
        # Disable registration in config
        self.app.config['REGISTRATION_ENABLED'] = False

        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        response = self.client.put('/' + API_VERSION_PREFIX + '/register', json=requestData, headers=createRegistrationInvitationCodeHttpHeader('AAAA-BBBB-CCCC-DDDD'))

        # Discard uncommitted changes to check if the changes has been committed
        db.session.rollback()

        assert response.status_code == 403
        assert User.query.get('alice-id') is None

    def test_register_user_missing_invitation_code(self):
        # Enable registration in config
        self.app.config['REGISTRATION_ENABLED'] = True

        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        response = self.client.put('/' + API_VERSION_PREFIX + '/register', json=requestData, headers={})

        # Discard uncommitted changes to check if the changes has been committed
        db.session.rollback()

        assert response.status_code == 403
        assert User.query.get('alice-id') is None

    def test_register_user_wrong_invitation_code(self):
        # Enable registration in config
        self.app.config['REGISTRATION_ENABLED'] = True

        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        response = self.client.put('/' + API_VERSION_PREFIX + '/register', json=requestData, headers=createRegistrationInvitationCodeHttpHeader('XXXX-YYYY-ZZZZ-AAAA'))

        # Discard uncommitted changes to check if the changes has been committed
        db.session.rollback()

        assert response.status_code == 403
        assert User.query.get('alice-id') is None

    def test_register_user_already_existing_user_by_existing_username(self):
        # Enable registration in config
        self.app.config['REGISTRATION_ENABLED'] = True

        alice = User('alice-id-1', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        initialUserJson = createUserJson(alice)

        requestData = {
            'id': 'alice-id-2',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        response = self.client.put('/' + API_VERSION_PREFIX + '/register', json=requestData, headers=createRegistrationInvitationCodeHttpHeader('AAAA-BBBB-CCCC-DDDD'))

        # Discard uncommitted changes to check if the changes has been committed
        db.session.rollback()

        assert response.status_code == 409
        assert createUserJson(User.query.get('alice-id-1')) == initialUserJson

    # Wrong field type tests

    def test_register_user_wrong_field_type_id(self):
        requestData = {
            'id': 1234,
            'username': 'alice',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_wrong_field_type(requestData)

    def test_register_user_wrong_field_type_username(self):
        requestData = {
            'id': 'alice-id',
            'username': 1234,
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_wrong_field_type(requestData)

    def test_register_user_wrong_field_type_fullName(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 1234,
            'serverComputedAuthenticationHash': 1234,
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_wrong_field_type(requestData)

    def test_register_user_wrong_field_type_serverComputedAuthenticationHash(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 1234,
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_wrong_field_type(requestData)

    def test_register_user_wrong_field_type_masterKeyDerivationInformation(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': None,
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_wrong_field_type(requestData)

    def test_register_user_wrong_field_type_masterEncryptionKey(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': None,
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_wrong_field_type(requestData)

    def test_register_user_wrong_field_type_itemEncryptionPublicKey(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': None,
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_wrong_field_type(requestData)

    def test_register_user_wrong_field_type_itemEncryptionSecretKey(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': None,
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_wrong_field_type(requestData)

    def test_register_user_wrong_field_type_settings(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': None,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_wrong_field_type(requestData)

    def test_register_user_wrong_field_type_deleted(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': 'this is not a boolean',
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_wrong_field_type(requestData)

    def test_register_user_wrong_field_type_modified(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 'this is not an integer',
            'created': 12345678901
        }
        self.__test_register_user_wrong_field_type(requestData)

    def test_register_user_wrong_field_type_created(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 'this is not an integer'
        }
        self.__test_register_user_wrong_field_type(requestData)

    def __test_register_user_wrong_field_type(self, requestData):
        # Enable registration in config
        self.app.config['REGISTRATION_ENABLED'] = True

        response = self.client.put('/' + API_VERSION_PREFIX + '/register', json=requestData, headers=createRegistrationInvitationCodeHttpHeader('AAAA-BBBB-CCCC-DDDD'))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert User.query.get('alice-id') is None

    # Missing field tests

    def test_register_user_missing_field_all(self):
        requestData = {}
        self.__test_register_user_missing_field(requestData)

    def test_register_user_missing_field_id(self):
        requestData = {
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_missing_field(requestData)

    def test_register_user_missing_field_username(self):
        requestData = {
            'id': 'alice-id',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_missing_field(requestData)

    def test_register_user_missing_field_fullName(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_missing_field(requestData)

    def test_register_user_missing_field_serverComputedAuthenticationHash(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_missing_field(requestData)

    def test_register_user_missing_field_masterKeyDerivationInformation(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_missing_field(requestData)

    def test_register_user_missing_field_masterEncryptionKey(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_missing_field(requestData)

    def test_register_user_missing_field_itemEncryptionPublicKey(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_missing_field(requestData)

    def test_register_user_missing_field_itemEncryptionSecretKey(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_missing_field(requestData)

    def test_register_user_missing_field_settings(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_missing_field(requestData)

    def test_register_user_missing_field_deleted(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_register_user_missing_field(requestData)

    def test_register_user_missing_field_modified(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'created': 12345678901
        }
        self.__test_register_user_missing_field(requestData)

    def test_register_user_missing_field_created(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902
        }
        self.__test_register_user_missing_field(requestData)

    def __test_register_user_missing_field(self, requestData):
        # Enable registration in config
        self.app.config['REGISTRATION_ENABLED'] = True

        response = self.client.put('/' + API_VERSION_PREFIX + '/register', json=requestData, headers=createRegistrationInvitationCodeHttpHeader('AAAA-BBBB-CCCC-DDDD'))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert User.query.get('alice-id') is None

    # Unknown field test

    def test_register_user_unknown_field(self):
        # Enable registration in config
        self.app.config['REGISTRATION_ENABLED'] = True

        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901,
            'foo': 'bar'
        }

        response = self.client.put('/' + API_VERSION_PREFIX + '/register', json=requestData, headers=createRegistrationInvitationCodeHttpHeader('AAAA-BBBB-CCCC-DDDD'))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert User.query.get('alice-id') is None

    # Invalid JSON test

    def test_register_user_invalid_json(self):
        # Enable registration in config
        self.app.config['REGISTRATION_ENABLED'] = True

        requestData = '{this is not valid JSON}'
        response = self.client.put('/' + API_VERSION_PREFIX + '/register', json=requestData, headers=createRegistrationInvitationCodeHttpHeader('AAAA-BBBB-CCCC-DDDD'))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert User.query.get('alice-id') is None

    """
    Tests for GET /token

    """

    def test_get_token_with_correct_credentials(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/' + API_VERSION_PREFIX + '/token', headers=createHttpBasicAuthHeaders('alice', '1234'))

        assert response.status_code == 200
        assert len(response.get_json().get('token')) == 177

    def test_get_token_with_deleted_user_record(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', True, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/' + API_VERSION_PREFIX + '/token', headers=createHttpBasicAuthHeaders('alice', '1234'))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_with_invalid_credentials(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/' + API_VERSION_PREFIX + '/token', headers=createHttpBasicAuthHeaders('alice', '1235'))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_with_valid_token(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/' + API_VERSION_PREFIX + '/token', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        # A token only can be requested with username and password
        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_without_authentication(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/' + API_VERSION_PREFIX + '/token')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_without_authentication_no_user_record(self):
        response = self.client.get('/' + API_VERSION_PREFIX + '/token')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    """
    Authentication tests (using GET /user)

    """

    def test_get_user_details_without_authentication(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/' + API_VERSION_PREFIX + '/user')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_details_without_authentication_no_user_record(self):
        response = self.client.get('/' + API_VERSION_PREFIX + '/user')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_details_unaccepted_password_authentication(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/' + API_VERSION_PREFIX + '/user', headers=createHttpBasicAuthHeaders('alice', '1234'))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_details_expired_token(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/' + API_VERSION_PREFIX + '/user', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice, -3600))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_details_token_without_signature(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/' + API_VERSION_PREFIX + '/user', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice, signatureAlgorithm='none'))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_deleted_user_record(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', True, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/' + API_VERSION_PREFIX + '/user', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    """
    Tests for GET /users

    """

    def test_get_users_one_user(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/' + API_VERSION_PREFIX + '/users', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200
        assert sortUserList(response.get_json()) == sortUserList([
            {'id': 'alice-id', 'username': 'alice', 'fullName': 'Alice Name', 'itemEncryptionPublicKey': 'a3', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ])

    def test_get_users_multiple_users(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy-id', 'sandy', 'Sandy Name', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678904, 12345678903)
        self.addUsers(alice, sandy)

        response = self.client.get('/' + API_VERSION_PREFIX + '/users', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200
        assert sortUserList(response.get_json()) == sortUserList([
            {'id': 'alice-id', 'username': 'alice', 'fullName': 'Alice Name', 'itemEncryptionPublicKey': 'a3', 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'id': 'sandy-id', 'username': 'sandy', 'fullName': 'Sandy Name', 'itemEncryptionPublicKey': 's3', 'deleted': False, 'modified': 12345678904, 'created': 12345678903}
        ])

    """
    Tests for GET /user

    """

    def test_get_user_details(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/' + API_VERSION_PREFIX + '/user', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200
        assert response.get_json() == {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

    """
    Tests for PUT /user

    """

    def test_set_user_details_change_multiple_fields(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x changed',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2 changed',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5 changed',
            'deleted': False,
            'modified': 12345678903,
            'created': 12345678901
        }

        response = self.client.put('/' + API_VERSION_PREFIX + '/user', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        # Discard uncommitted changes to check if the changes has been committed
        db.session.rollback()

        assert response.status_code == 204
        assert createUserJson(User.query.get('alice-id')) == requestData

    # Modify field tests

    def test_set_user_details_change_field_username(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice changed',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        # The field is immutable
        expected = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        self.__test_set_user_details_change_field(requestData, expected)

    def test_set_user_details_change_field_fullName(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name changed',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        expected = requestData

        self.__test_set_user_details_change_field(requestData, expected)

    def test_set_user_details_change_field_serverComputedAuthenticationHash(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x changed',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        expected = requestData

        self.__test_set_user_details_change_field(requestData, expected)

    def test_set_user_details_change_field_masterKeyDerivationInformation(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1 changed',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        # The field is immutable
        expected = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        self.__test_set_user_details_change_field(requestData, expected)

    def test_set_user_details_change_field_masterEncryptionKey(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2 changed',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        expected = requestData

        self.__test_set_user_details_change_field(requestData, expected)

    def test_set_user_details_change_field_itemEncryptionPublicKey(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3 changed',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        # The field is immutable
        expected = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        self.__test_set_user_details_change_field(requestData, expected)

    def test_set_user_details_change_field_itemEncryptionSecretKey(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4 changed',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        # The field is immutable
        expected = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        self.__test_set_user_details_change_field(requestData, expected)

    def test_set_user_details_change_field_settings(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5 changed',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        expected = requestData

        self.__test_set_user_details_change_field(requestData, expected)

    def test_set_user_details_change_field_deleted(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': True,
            'modified': 12345678902,
            'created': 12345678901
        }

        # The field is immutable
        expected = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        self.__test_set_user_details_change_field(requestData, expected)

    def test_set_user_details_change_field_modified(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678903,
            'created': 12345678901
        }

        expected = requestData

        self.__test_set_user_details_change_field(requestData, expected)

    def test_set_user_details_change_field_created(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678902
        }

        # The field is immutable
        expected = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        self.__test_set_user_details_change_field(requestData, expected)

    def __test_set_user_details_change_field(self, requestData, expected):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.put('/' + API_VERSION_PREFIX + '/user', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204
        assert createUserJson(User.query.get('alice-id')) == expected

    # Wrong field type tests

    def test_set_user_details_wrong_field_type_id(self):
        requestData = {
            'id': 1234,
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_wrong_field_type(requestData)

    def test_set_user_details_wrong_field_type_username(self):
        requestData = {
            'id': 'alice-id',
            'username': 1234,
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_wrong_field_type(requestData)

    def test_set_user_details_wrong_field_type_fullName(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 1234,
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_wrong_field_type(requestData)

    def test_set_user_details_wrong_field_type_serverComputedAuthenticationHash(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 1234,
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_wrong_field_type(requestData)

    def test_set_user_details_wrong_field_type_masterKeyDerivationInformation(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': None,
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_wrong_field_type(requestData)

    def test_set_user_details_wrong_field_type_masterEncryptionKey(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': None,
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_wrong_field_type(requestData)

    def test_set_user_details_wrong_field_type_itemEncryptionPublicKey(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': None,
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_wrong_field_type(requestData)

    def test_set_user_details_wrong_field_type_itemEncryptionSecretKey(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': None,
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_wrong_field_type(requestData)

    def test_set_user_details_wrong_field_type_settings(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': None,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_wrong_field_type(requestData)

    def test_set_user_details_wrong_field_type_deleted(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': 'this is not a boolean',
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_wrong_field_type(requestData)

    def test_set_user_details_wrong_field_type_modified(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 'this is not an integer',
            'created': 12345678901
        }
        self.__test_set_user_details_wrong_field_type(requestData)

    def test_set_user_details_wrong_field_type_created(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 'this is not an integer'
        }
        self.__test_set_user_details_wrong_field_type(requestData)

    def __test_set_user_details_wrong_field_type(self, requestData):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        initialUserJson = createUserJson(alice)

        response = self.client.put('/' + API_VERSION_PREFIX + '/user', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert createUserJson(User.query.get('alice-id')) == initialUserJson

    # Missing field tests

    def test_set_user_details_missing_field_all(self):
        requestData = {}
        self.__test_set_user_details_missing_field(requestData)

    def test_set_user_details_missing_field_id(self):
        requestData = {
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_missing_field(requestData)

    def test_set_user_details_missing_field_username(self):
        requestData = {
            'id': 'alice-id',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_missing_field(requestData)

    def test_set_user_details_missing_field_fullName(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_missing_field(requestData)

    def test_set_user_details_missing_field_serverComputedAuthenticationHash(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_missing_field(requestData)

    def test_set_user_details_missing_field_masterKeyDerivationInformation(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_missing_field(requestData)

    def test_set_user_details_missing_field_masterEncryptionKey(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_missing_field(requestData)

    def test_set_user_details_missing_field_itemEncryptionPublicKey(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_missing_field(requestData)

    def test_set_user_details_missing_field_itemEncryptionSecretKey(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_missing_field(requestData)

    def test_set_user_details_missing_field_settings(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_missing_field(requestData)

    def test_set_user_details_missing_field_deleted(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'modified': 12345678902,
            'created': 12345678901
        }
        self.__test_set_user_details_missing_field(requestData)

    def test_set_user_details_missing_field_modified(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'created': 12345678901
        }
        self.__test_set_user_details_missing_field(requestData)

    def test_set_user_details_missing_field_created(self):
        requestData = {
            'id': 'alice-id',
            'username': 'alice',
            'fullName': 'Alice Name',
            'serverComputedAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902
        }
        self.__test_set_user_details_missing_field(requestData)

    def __test_set_user_details_missing_field(self, requestData):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        initialUserJson = createUserJson(alice)

        response = self.client.put('/' + API_VERSION_PREFIX + '/user', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert createUserJson(User.query.get('alice-id')) == initialUserJson

    # Unknown field test

    def test_set_user_details_unknown_field(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        initialUserJson = createUserJson(alice)

        userJson = createUserJson(alice)
        userJson['foo'] = 'bar'
        requestData = userJson
        response = self.client.put('/' + API_VERSION_PREFIX + '/user', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert createUserJson(User.query.get('alice-id')) == initialUserJson

    # Invalid JSON test

    def test_set_user_details_invalid_json(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        initialUserJson = createUserJson(alice)

        requestData = '{this is not valid JSON}'
        response = self.client.put('/' + API_VERSION_PREFIX + '/user', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert createUserJson(User.query.get('alice-id')) == initialUserJson

    """
    Tests for GET /user/items

    """

    def test_get_user_items(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(
            Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901)
        )

        self.addItemAuthorizations(
            ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901)
        )

        response = self.client.get('/' + API_VERSION_PREFIX + '/user/items', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))
        assert response.status_code == 200
        assert sortItemList(response.get_json()) == sortItemList([
            {'id': 'item1', 'userId': 'alice-id', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ])

    def test_get_user_items_with_deleted_item(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(
            Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901),
            Item('item2', 'alice-id', 'example data 2', True, 12345678902, 12345678901),
        )

        self.addItemAuthorizations(
            ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization2', 'alice-id', 'item2', 'example item key 2', False, False, 12345678902, 12345678901)
        )

        response = self.client.get('/' + API_VERSION_PREFIX + '/user/items', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200

        # The "item2" is deleted, but is listed of course
        assert sortItemList(response.get_json()) == sortItemList([
            {'id': 'item1', 'userId': 'alice-id', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'id': 'item2', 'userId': 'alice-id', 'data': 'example data 2', 'deleted': True, 'modified': 12345678902, 'created': 12345678901}
        ])

    def test_get_user_items_without_any_item_authorization(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(
            Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901)
        )

        response = self.client.get('/' + API_VERSION_PREFIX + '/user/items', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))
        assert response.status_code == 200

        # Alice is not able to see "item1" because no item authorization exists
        assert sortItemList(response.get_json()) == sortItemList([])

    def test_get_user_items_without_shared_item_authorization(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy-id', 'sandy', 'Sandy Name', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(
            Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901),
            Item('item2', 'sandy-id', 'example data 2', False, 12345678902, 12345678901),
        )

        self.addItemAuthorizations(
            ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization2', 'sandy-id', 'item2', 'example item key 2', False, False, 12345678902, 12345678901)
        )

        response = self.client.get('/' + API_VERSION_PREFIX + '/user/items', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200

        # Alice is only able to see "item1", because Sandy does not shared "item2" with her
        assert sortItemList(response.get_json()) == sortItemList([
            {'id': 'item1', 'userId': 'alice-id', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ])

    def test_get_user_items_with_shared_item_authorization(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy-id', 'sandy', 'Sandy Name', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(
            Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901),
            Item('item2', 'sandy-id', 'example data 2', False, 12345678902, 12345678901),
        )

        self.addItemAuthorizations(
            ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization2', 'sandy-id', 'item2', 'example item key 2', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization3', 'alice-id', 'item2', 'example item key 2', False, False, 12345678902, 12345678901)
        )

        response = self.client.get('/' + API_VERSION_PREFIX + '/user/items', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200

        # The "item2" of Sandy is also accessible by Alice because she has a non-deleted item authorization
        assert sortItemList(response.get_json()) == sortItemList([
            {'id': 'item1', 'userId': 'alice-id', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'id': 'item2', 'userId': 'sandy-id', 'data': 'example data 2', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ])

    def test_get_user_items_with_deleted_shared_item_authorization(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy-id', 'sandy', 'Sandy Name', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(
            Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901),
            Item('item2', 'sandy-id', 'example data 2', False, 12345678902, 12345678901),
        )

        self.addItemAuthorizations(
            ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization2', 'sandy-id', 'item2', 'example item key 2', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization3', 'alice-id', 'item2', 'example item key 2', False, True, 12345678902, 12345678901)
        )

        response = self.client.get('/' + API_VERSION_PREFIX + '/user/items', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200

        # The "item2" of Sandy is not accessible by Alice anymore because item authorization was deleted by Sandy
        assert sortItemList(response.get_json()) == sortItemList([
            {'id': 'item1', 'userId': 'alice-id', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ])

    """
    Tests for PUT /user/items

    """

    # Create new items tests

    def test_set_user_items_create_items(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        item1Json = {
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example item data 1',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        item2Json = {
            'id': 'item2',
            'userId': 'alice-id',
            'data': 'example item data 2',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        requestData = [item1Json, item2Json]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/items', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204
        assert createItemJson(Item.query.get('item1')) == item1Json
        assert createItemJson(Item.query.get('item2')) == item2Json

    def test_set_user_items_create_deleted_item(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        item1Json = {
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example item data 1',
            'deleted': True,
            'modified': 12345678902,
            'created': 12345678901
        }

        requestData = [item1Json]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/items', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204
        assert createItemJson(Item.query.get('item1')) == item1Json

    def test_set_user_items_create_item_with_not_existing_user(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        item1Json = {
            'id': 'item1',
            'userId': 'notExistingUser',
            'data': 'example item data 1',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        requestData = [item1Json]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/items', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 404
        assert response.get_json() == {'error': 'Not found'}
        assert Item.query.get('item1') is None

    # Permission tests

    def test_set_user_items_create_item_for_other_user(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy-id', 'sandy', 'Sandy Name', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        item1Json = {
            'id': 'item1',
            'userId': 'sandy-id',
            'data': 'example item data 1',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        requestData = [item1Json]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/items', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        # Alice is not allowed to create a item for another user (Sandy)
        assert response.status_code == 403
        assert response.get_json() == {'error': 'Forbidden'}
        assert Item.query.get('item1') is None

    def test_set_user_items_change_item_without_item_authorization(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        item1 = Item('item1', 'alice-id', 'example item data 1', False, 12345678902, 12345678901)
        self.addItems(item1)

        initialItem1Json = createItemJson(item1)

        item1Json = {
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example item data 1a',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        requestData = [item1Json]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/items', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 403
        assert response.get_json() == {'error': 'Forbidden'}
        assert createItemJson(Item.query.get('item1')) == initialItem1Json

    def test_set_user_items_change_item_with_readonly_item_authorization(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        item1 = Item('item1', 'alice-id', 'example item data 1', False, 12345678902, 12345678901)
        self.addItems(item1)

        initialItem1Json = createItemJson(item1)

        self.addItemAuthorizations(
            ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', True, False, 12345678902, 12345678901)
        )

        item1Json = {
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example item data 1a',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        requestData = [item1Json]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/items', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 403
        assert response.get_json() == {'error': 'Forbidden'}
        assert createItemJson(Item.query.get('item1')) == initialItem1Json

    def test_set_user_items_change_item_with_deleted_item_authorization(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        item1 = Item('item1', 'alice-id', 'example item data 1', False, 12345678902, 12345678901)
        self.addItems(item1)

        initialItem1Json = createItemJson(item1)

        self.addItemAuthorizations(
            ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, True, 12345678902, 12345678901)
        )

        item1Json = {
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example item data 1a',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        requestData = [item1Json]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/items', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 403
        assert response.get_json() == {'error': 'Forbidden'}
        assert createItemJson(Item.query.get('item1')) == initialItem1Json

    # Modify field tests

    def test_set_user_items_change_field_userId_existing(self):
        requestData = [{
            'id': 'item1',
            'userId': 'sandy-id',
            'data': 'example data 1',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]

        # The field is immutable
        expected = {
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example data 1',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        self.__test_set_user_items_change_field(requestData, expected)

    def test_set_user_items_change_field_userId_not_existing(self):
        requestData = [{
            'id': 'item1',
            'userId': 'notExistingUser',
            'data': 'example data 1',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]

        # The field is immutable
        expected = {
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example data 1',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        self.__test_set_user_items_change_field(
            requestData=requestData,
            expected=expected,
            expectedStatusCode=404,
            expectedResponseJson={'error': 'Not found'}
        )

    def test_set_user_items_change_field_data(self):
        requestData = [{
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example data 1 changed',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        expected = requestData[0]
        self.__test_set_user_items_change_field(requestData, expected)

    def test_set_user_items_change_field_deleted(self):
        requestData = [{
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example data 1',
            'deleted': True,
            'modified': 12345678902,
            'created': 12345678901
        }]
        expected = requestData[0]
        self.__test_set_user_items_change_field(requestData, expected)

    def test_set_user_items_change_field_modified(self):
        requestData = [{
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example data 1',
            'deleted': False,
            'modified': 12345678903,
            'created': 12345678901
        }]
        expected = requestData[0]
        self.__test_set_user_items_change_field(requestData, expected)

    def test_set_user_items_change_field_created(self):
        requestData = [{
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example data 1',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678903
        }]

        # The field is immutable
        expected = {
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example data 1',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        self.__test_set_user_items_change_field(requestData, expected)

    def __test_set_user_items_change_field(
        self,
        requestData,
        expected,
        expectedStatusCode=204,
        expectedResponseJson=None
    ):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy-id', 'sandy', 'Sandy Name', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901))
        self.addItemAuthorizations(ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901))

        response = self.client.put('/' + API_VERSION_PREFIX + '/user/items', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == expectedStatusCode
        assert response.get_json() == expectedResponseJson
        assert createItemJson(Item.query.get('item1')) == expected

    # Wrong field type tests

    def test_set_user_items_wrong_field_type_id(self):
        requestData = [{
            'id': 1234,
            'userId': 'alice-id',
            'data': 'example data 1',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_items_wrong_field_type(requestData)

    def test_set_user_items_wrong_field_type_userId(self):
        requestData = [{
            'id': 'item1',
            'userId': 1234,
            'data': 'example data 1',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_items_wrong_field_type(requestData)

    def test_set_user_items_wrong_field_type_data(self):
        requestData = [{
            'id': 'item1',
            'userId': 'alice-id',
            'data': None,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_items_wrong_field_type(requestData)

    def test_set_user_items_wrong_field_type_deleted(self):
        requestData = [{
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example data 1',
            'deleted': 'this is not a boolean',
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_items_wrong_field_type(requestData)

    def test_set_user_items_wrong_field_type_modified(self):
        requestData = [{
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example data 1',
            'deleted': False,
            'modified': 'this is not an integer',
            'created': 12345678901
        }]
        self.__test_set_user_items_wrong_field_type(requestData)

    def test_set_user_items_wrong_field_type_created(self):
        requestData = [{
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example data 1',
            'deleted': False,
            'modified': 12345678902,
            'created': 'this is not an integer'
        }]
        self.__test_set_user_items_wrong_field_type(requestData)

    def __test_set_user_items_wrong_field_type(self, requestData):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        item1 = Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901)
        self.addItems(item1)

        initialItem1Json = createItemJson(item1)

        self.addItemAuthorizations(ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901))

        response = self.client.put('/' + API_VERSION_PREFIX + '/user/items', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert createItemJson(Item.query.get('item1')) == initialItem1Json

    # Missing field tests

    def test_set_user_items_missing_field_all(self):
        requestData = [{}]
        self.__test_set_user_items_missing_field(requestData)

    def test_set_user_items_missing_field_id(self):
        requestData = [{
            'userId': 'alice-id',
            'data': 'example data 1',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_items_missing_field(requestData)

    def test_set_user_items_missing_field_userId(self):
        requestData = [{
            'id': 'item1',
            'data': 'example data 1',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_items_missing_field(requestData)

    def test_set_user_items_missing_field_data(self):
        requestData = [{
            'id': 'item1',
            'userId': 'alice-id',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_items_missing_field(requestData)

    def test_set_user_items_missing_field_deleted(self):
        requestData = [{
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example data 1',
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_items_missing_field(requestData)

    def test_set_user_items_missing_field_modified(self):
        requestData = [{
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example data 1',
            'deleted': False,
            'created': 12345678901
        }]
        self.__test_set_user_items_missing_field(requestData)

    def test_set_user_items_missing_field_created(self):
        requestData = [{
            'id': 'item1',
            'userId': 'alice-id',
            'data': 'example data 1',
            'deleted': False,
            'modified': 12345678902
        }]
        self.__test_set_user_items_missing_field(requestData)

    def __test_set_user_items_missing_field(self, requestData):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        item1 = Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901)
        self.addItems(item1)

        initialItem1Json = createItemJson(item1)

        self.addItemAuthorizations(ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901))

        response = self.client.put('/' + API_VERSION_PREFIX + '/user/items', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert createItemJson(Item.query.get('item1')) == initialItem1Json

    # Unknown field test

    def test_set_user_items_unknown_field(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        item1 = Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901)
        self.addItems(item1)

        initialItem1Json = createItemJson(item1)

        self.addItemAuthorizations(ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901))

        item1Json = createItemJson(item1)
        item1Json['foo'] = 'bar'
        requestData = [item1Json]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/items', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert createItemJson(Item.query.get('item1')) == initialItem1Json

    # Invalid JSON test

    def test_set_user_items_invalid_json(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        item1 = Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901)
        self.addItems(item1)

        initialItem1Json = createItemJson(item1)

        self.addItemAuthorizations(ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901))

        requestData = '[{this is not valid JSON]'
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/items', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert createItemJson(Item.query.get('item1')) == initialItem1Json

    """
    Tests for GET /user/itemauthorizations

    """

    def test_get_user_item_authorizations(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy-id', 'sandy', 'Sandy Name', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(
            Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901),
            Item('item2', 'alice-id', 'example data 2', False, 12345678902, 12345678901),
            Item('item3', 'sandy-id', 'example data 3', False, 12345678902, 12345678901)
        )

        self.addItemAuthorizations(
            ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901),

            # Alice gave herself and Sandy access to "item2"
            ItemAuthorization('itemAuthorization2', 'alice-id', 'item2', 'example item key 2', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization3', 'sandy-id', 'item2', 'example item key 2', False, False, 12345678902, 12345678901),

            # Sandy gave herself and Alice access to "item3" but deleted Alice item authorization
            ItemAuthorization('itemAuthorization4', 'sandy-id', 'item3', 'example item key 3', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization5', 'alice-id', 'item3', 'example item key 3', False, True, 12345678902, 12345678901)
        )

        response = self.client.get('/' + API_VERSION_PREFIX + '/user/itemauthorizations', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200

        # Alice see the item authorizations created from and for her (also the deleted ones)
        assert sortItemAuthorizationList(response.get_json()) == sortItemAuthorizationList([
            {'id': 'itemAuthorization1', 'userId': 'alice-id', 'itemId': 'item1', 'itemKey': 'example item key 1', 'readOnly': False, 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'id': 'itemAuthorization2', 'userId': 'alice-id', 'itemId': 'item2', 'itemKey': 'example item key 2', 'readOnly': False, 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'id': 'itemAuthorization3', 'userId': 'sandy-id', 'itemId': 'item2', 'itemKey': 'example item key 2', 'readOnly': False, 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'id': 'itemAuthorization5', 'userId': 'alice-id', 'itemId': 'item3', 'itemKey': 'example item key 3', 'readOnly': False, 'deleted': True, 'modified': 12345678902, 'created': 12345678901}
        ])

    """
    Tests for PUT /user/itemauthorizations

    """

    # Create new item authorization tests

    def test_set_user_item_authorizations_create_authorizations(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(
            Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901),
            Item('item2', 'alice-id', 'example data 2', False, 12345678902, 12345678901)
        )

        itemAuthorization1Json = {
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        itemAuthorization2Json = {
            'id': 'itemAuthorization2',
            'userId': 'alice-id',
            'itemId': 'item2',
            'itemKey': 'example item key 2',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        requestData = [itemAuthorization1Json, itemAuthorization2Json]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == itemAuthorization1Json
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization2')) == itemAuthorization2Json

    def test_set_user_item_authorizations_create_authorization_for_other_user(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy-id', 'sandy', 'Sandy Name', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901))
        self.addItemAuthorizations(ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901))

        itemAuthorization2Json = {
            'id': 'itemAuthorization2',
            'userId': 'sandy-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        requestData = [itemAuthorization2Json]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization2')) == itemAuthorization2Json

    def test_set_user_item_authorizations_create_deleted_authorization(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901))

        itemAuthorization1Json = {
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': True,
            'modified': 12345678902,
            'created': 12345678901
        }

        requestData = [itemAuthorization1Json]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == itemAuthorization1Json

    def test_set_user_item_authorizations_create_authorization_with_not_existing_user(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901))

        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'notExistingUser',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 404
        assert response.get_json() == {'error': 'Not found'}
        assert ItemAuthorization.query.get('itemAuthorization1') is None

    def test_set_user_item_authorizations_create_authorization_with_not_existing_item(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901))

        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'notExistingItem',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 404
        assert response.get_json() == {'error': 'Not found'}
        assert ItemAuthorization.query.get('itemAuthorization1') is None

    def test_set_user_item_authorizations_create_authorization_for_item_with_already_existing_item_authorization_for_requesting_user(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901))
        self.addItemAuthorizations(ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901))

        requestData = [{
            'id': 'itemAuthorization1a',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert ItemAuthorization.query.get('itemAuthorization1a') is None

    def test_set_user_item_authorizations_create_authorization_for_item_with_already_existing_item_authorization_for_other_user(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy-id', 'sandy', 'Sandy Name', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901))
        self.addItemAuthorizations(
            ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization2', 'sandy-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901)
        )

        requestData = [{
            'id': 'itemAuthorization2a',
            'userId': 'sandy-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert ItemAuthorization.query.get('itemAuthorization2a') is None

    # Permission tests

    def test_set_user_item_authorizations_create_authorization_for_item_is_owned_by_other_user(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy-id', 'sandy', 'Sandy Name', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(Item('item1', 'sandy-id', 'example data 1', False, 12345678902, 12345678901))

        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        # Alice is not allowed to create a item authorization for an item that is not owned by her
        assert response.status_code == 403
        assert response.get_json() == {'error': 'Forbidden'}
        assert ItemAuthorization.query.get('itemAuthorization1') is None

    def test_set_user_item_authorizations_update_authorization_for_item_is_owned_by_other_user(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy-id', 'sandy', 'Sandy Name', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(Item('item1', 'sandy-id', 'example data 1', False, 12345678902, 12345678901))

        itemAuthorization1 = ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', True, False, 12345678902, 12345678901)
        self.addItemAuthorizations(itemAuthorization1)

        initialItemAuthorization1Json = createItemAuthorizationJson(itemAuthorization1)

        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        # Alice is not allowed to change item authorization for her for an item that is not owned by her
        assert response.status_code == 403
        assert response.get_json() == {'error': 'Forbidden'}
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == initialItemAuthorization1Json

    # Modify field tests

    def test_set_user_item_authorizations_change_field_userId_existing(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'sandy-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]

        # The field is immutable
        expected = {
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        self.__test_set_user_item_authorizations_change_field(requestData, expected)

    def test_set_user_item_authorizations_change_field_userId_not_existing(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'notExistingUser',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]

        # The field is immutable
        expected = {
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        self.__test_set_user_item_authorizations_change_field(
            requestData=requestData,
            expected=expected,
            expectedStatusCode=404,
            expectedResponseJson={'error': 'Not found'}
        )

    def test_set_user_item_authorizations_change_field_itemId_existing(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item2',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]

        # The field is immutable
        expected = {
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        self.__test_set_user_item_authorizations_change_field(requestData, expected)

    def test_set_user_item_authorizations_change_field_itemId_not_existing(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'notExistingItem',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]

        # The field is immutable
        expected = {
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        self.__test_set_user_item_authorizations_change_field(
            requestData=requestData,
            expected=expected,
            expectedStatusCode=404,
            expectedResponseJson={'error': 'Not found'}
        )

    def test_set_user_item_authorizations_change_field_itemKey(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1 changed',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]

        # The field is immutable
        expected = {
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        self.__test_set_user_item_authorizations_change_field(requestData, expected)

    def test_set_user_item_authorizations_change_field_readOnly(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': True,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        expected = requestData[0]
        self.__test_set_user_item_authorizations_change_field(requestData, expected)

    def test_set_user_item_authorizations_change_field_deleted(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': True,
            'modified': 12345678902,
            'created': 12345678901
        }]
        expected = requestData[0]
        self.__test_set_user_item_authorizations_change_field(requestData, expected)

    def test_set_user_item_authorizations_change_field_modified(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678903,
            'created': 12345678901
        }]
        expected = requestData[0]
        self.__test_set_user_item_authorizations_change_field(requestData, expected)

    def test_set_user_item_authorizations_change_field_created(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678902
        }]

        # The field is immutable
        expected = {
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        self.__test_set_user_item_authorizations_change_field(requestData, expected)

    def __test_set_user_item_authorizations_change_field(
        self,
        requestData,
        expected,
        expectedStatusCode=204,
        expectedResponseJson=None
    ):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy-id', 'sandy', 'Sandy Name', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(
            Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901),
            Item('item2', 'alice-id', 'example data 2', False, 12345678902, 12345678901)
        )

        self.addItemAuthorizations(ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901))

        response = self.client.put('/' + API_VERSION_PREFIX + '/user/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == expectedStatusCode
        assert response.get_json() == expectedResponseJson
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == expected

    # Wrong field type tests

    def test_set_user_item_authorizations_wrong_field_type_id(self):
        requestData = [{
            'id': 1234,
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_item_authorizations_wrong_field_type(requestData)

    def test_set_user_item_authorizations_wrong_field_type_userId(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 1234,
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_item_authorizations_wrong_field_type(requestData)

    def test_set_user_item_authorizations_wrong_field_type_itemId(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 1234,
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_item_authorizations_wrong_field_type(requestData)

    def test_set_user_item_authorizations_wrong_field_type_itemKey(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': None,
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_item_authorizations_wrong_field_type(requestData)

    def test_set_user_item_authorizations_wrong_field_type_readOnly(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': 'this is not a boolean',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_item_authorizations_wrong_field_type(requestData)

    def test_set_user_item_authorizations_wrong_field_type_deleted(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': 'this is not a boolean',
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_item_authorizations_wrong_field_type(requestData)

    def test_set_user_item_authorizations_wrong_field_type_modified(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 'this is not an integer',
            'created': 12345678901
        }]
        self.__test_set_user_item_authorizations_wrong_field_type(requestData)

    def test_set_user_item_authorizations_wrong_field_type_created(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 'this is not an integer'
        }]
        self.__test_set_user_item_authorizations_wrong_field_type(requestData)

    def __test_set_user_item_authorizations_wrong_field_type(self, requestData):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901))

        itemAuthorization1 = ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901)
        self.addItemAuthorizations(itemAuthorization1)

        initialItemAuthorization1Json = createItemAuthorizationJson(itemAuthorization1)

        response = self.client.put('/' + API_VERSION_PREFIX + '/user/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == initialItemAuthorization1Json

    # Missing field tests

    def test_set_user_item_authorizations_missing_field_all(self):
        requestData = [{}]
        self.__test_set_user_item_authorizations_missing_field(requestData)

    def test_set_user_item_authorizations_missing_field_id(self):
        requestData = [{
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': True,
            'deleted': True,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_item_authorizations_missing_field(requestData)

    def test_set_user_item_authorizations_missing_field_userId(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': True,
            'deleted': True,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_item_authorizations_missing_field(requestData)

    def test_set_user_item_authorizations_missing_field_itemId(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemKey': 'example item key 1',
            'readOnly': True,
            'deleted': True,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_item_authorizations_missing_field(requestData)

    def test_set_user_item_authorizations_missing_field_itemKey(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'readOnly': True,
            'deleted': True,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_item_authorizations_missing_field(requestData)

    def test_set_user_item_authorizations_missing_field_readOnly(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'deleted': True,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_item_authorizations_missing_field(requestData)

    def test_set_user_item_authorizations_missing_field_deleted(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': True,
            'modified': 12345678902,
            'created': 12345678901
        }]
        self.__test_set_user_item_authorizations_missing_field(requestData)

    def test_set_user_item_authorizations_missing_field_modified(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': True,
            'deleted': True,
            'created': 12345678901
        }]
        self.__test_set_user_item_authorizations_missing_field(requestData)

    def test_set_user_item_authorizations_missing_field_created(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice-id',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': True,
            'deleted': True,
            'modified': 12345678902
        }]
        self.__test_set_user_item_authorizations_missing_field(requestData)

    def __test_set_user_item_authorizations_missing_field(self, requestData):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901))

        itemAuthorization1 = ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901)
        self.addItemAuthorizations(itemAuthorization1)

        initialItemAuthorization1Json = createItemAuthorizationJson(itemAuthorization1)

        response = self.client.put('/' + API_VERSION_PREFIX + '/user/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == initialItemAuthorization1Json

    # Unknown field test

    def test_set_user_item_authorizations_unknown_field(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901))

        itemAuthorization1 = ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901)
        self.addItemAuthorizations(itemAuthorization1)

        initialItemAuthorization1Json = createItemAuthorizationJson(itemAuthorization1)

        itemAuthorization1Json = createItemAuthorizationJson(itemAuthorization1)
        itemAuthorization1Json['foo'] = 'bar'
        requestData = [itemAuthorization1Json]
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == initialItemAuthorization1Json

    # Invalid JSON test

    def test_set_user_item_authorizations_invalid_json(self):
        alice = User('alice-id', 'alice', 'Alice Name', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice-id', 'example data 1', False, 12345678902, 12345678901))

        itemAuthorization1 = ItemAuthorization('itemAuthorization1', 'alice-id', 'item1', 'example item key 1', False, False, 12345678902, 12345678901)
        self.addItemAuthorizations(itemAuthorization1)

        initialItemAuthorization1Json = createItemAuthorizationJson(itemAuthorization1)

        requestData = '[{this is not valid JSON]'
        response = self.client.put('/' + API_VERSION_PREFIX + '/user/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == initialItemAuthorization1Json
