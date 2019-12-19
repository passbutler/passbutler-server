#!/usr/bin/env python3

from flask_testing import TestCase
from passbutlerserver import createApp, db
from passbutlerserver import User, Item, ItemAuthorization
from itsdangerous import TimedJSONWebSignatureSerializer
import base64
import unittest

class PassButlerTestCase(TestCase):

    TESTING = True

    SQLALCHEMY_DATABASE_URI = 'sqlite://'

    SERVER_HOST = ''
    SERVER_PORT = 0
    SECRET_KEY = 'This is the secret key for testing'

    def create_app(self):
        app = createApp(self)
        return app

    def setUp(self):
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

"""
Model to JSON functions

"""

def createUserJson(user):
    return {
        'username': user.username,
        'masterPasswordAuthenticationHash': user.masterPasswordAuthenticationHash,
        'masterKeyDerivationInformation': user.masterKeyDerivationInformation,
        'masterEncryptionKey': user.masterEncryptionKey,
        'itemEncryptionPublicKey': user.itemEncryptionPublicKey,
        'itemEncryptionSecretKey': user.itemEncryptionSecretKey,
        'settings': user.settings,
        'deleted': user.deleted,
        'modified': user.modified,
        'created': user.created
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
    return sorted(userList, key=lambda k: k['username'])

def sortItemList(itemList):
    return sorted(itemList, key=lambda k: k['id'])

def sortItemAuthorizationList(itemAuthorizationList):
    return sorted(itemAuthorizationList, key=lambda k: k['id'])

"""
Authentication helpers

"""

def createHttpBasicAuthHeaders(username, password):
    credentialBytes = (username + ':' + password).encode()
    base64EncodedCredentials = base64.b64encode(credentialBytes).decode('utf-8')
    return {'Authorization': 'Basic ' + base64EncodedCredentials}

def createHttpTokenAuthHeaders(secretKey, user, expiresIn=3600, signatureAlgorithm="HS512"):
    tokenSerializer = TimedJSONWebSignatureSerializer(secretKey, expires_in=expiresIn, algorithm_name=signatureAlgorithm)
    token = user.generateAuthenticationToken(tokenSerializer)
    return {'Authorization': 'Bearer ' + token}

class UserTests(PassButlerTestCase):

    def addUsers(self, *users):
        for user in users:
            db.session.add(user)

        db.session.commit()   

    def addItems(self, *items):
        for item in items:
            db.session.add(item)

        db.session.commit()  

    def addItemAuthorizations(self, *itemAuthorizations):
        for itemAuthorization in itemAuthorizations:
            db.session.add(itemAuthorization)

        db.session.commit() 

    """
    Tests for GET /token

    """

    def test_get_token_with_correct_credentials(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/token', headers=createHttpBasicAuthHeaders('alice', '1234'))

        assert response.status_code == 200
        assert len(response.get_json().get('token')) == 181

    def test_get_token_with_deleted_user_record(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', True, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/token', headers=createHttpBasicAuthHeaders('alice', '1234'))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_with_invalid_credentials(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/token', headers=createHttpBasicAuthHeaders('alice', '1235'))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_with_valid_token(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/token', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        ## A token only can be requested with username and password
        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_without_authentication(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/token')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_without_authentication_no_user_record(self):
        response = self.client.get('/token')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    """
    Authentication tests (using GET /userdetails)

    """

    def test_get_user_details_without_authentication(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/userdetails')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_details_without_authentication_no_user_record(self):
        response = self.client.get('/userdetails')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_details_unaccepted_password_authentication(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/userdetails', headers=createHttpBasicAuthHeaders('alice', '1234'))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_details_expired_token(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/userdetails', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice, -3600))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_details_token_without_signature(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/userdetails', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice, signatureAlgorithm="none"))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_deleted_user_record(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', True, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/userdetails', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    """
    Tests for GET /users

    """

    def test_get_users_one_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/users', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200
        assert sortUserList(response.get_json()) == sortUserList([
            {'username': 'alice', 'itemEncryptionPublicKey': 'a3', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ])

    def test_get_users_multiple_users(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678904, 12345678903)
        self.addUsers(alice, sandy)

        response = self.client.get('/users', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200
        assert sortUserList(response.get_json()) == sortUserList([
            {'username': 'alice', 'itemEncryptionPublicKey': 'a3', 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'username': 'sandy', 'itemEncryptionPublicKey': 's3', 'deleted': False, 'modified': 12345678904, 'created': 12345678903}
        ])

    """
    Tests for GET /userdetails

    """

    def test_get_user_details(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/userdetails', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200
        assert response.get_json() == {
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
    Tests for PUT /userdetails

    """

    def test_set_user_details_change_multiple_fields(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        requestData = {
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x changed',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2 changed',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5 changed',
            'deleted': False,
            'modified': 12345678903,
            'created': 12345678901
        }

        response = self.client.put('/userdetails', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        ## Discard uncommited changes to check if the changes has been committed
        db.session.rollback()

        assert response.status_code == 204
        assert createUserJson(User.query.get('alice')) == requestData

    ## General modify field tests

    def test_set_user_details_change_field_masterPasswordAuthenticationHash(self):
        requestData = {
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x changed',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1 changed',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        expected = {
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3 changed',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        expected = {
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4 changed',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        expected = {
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': True,
            'modified': 12345678902,
            'created': 12345678901
        }

        expected = {
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678902
        }

        expected = {
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.put('/userdetails', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204
        assert createUserJson(User.query.get('alice')) == expected

    ## General wrong field type tests

    def test_set_user_details_wrong_field_type_username(self):
        requestData = {
            'username': 1234,
            'masterPasswordAuthenticationHash': 'x',
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

    def test_set_user_details_wrong_field_type_masterPasswordAuthenticationHash(self):
        requestData = {
            'username': 'alice',
            'masterPasswordAuthenticationHash': 1234,
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        initialUserJson = createUserJson(alice)

        response = self.client.put('/userdetails', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}

        ## Be sure, nothing was changed
        assert createUserJson(User.query.get('alice')) == initialUserJson

    ## General missing field tests

    def test_set_user_details_missing_field_all(self):
        requestData = {}
        self.__test_set_user_details_missing_field(requestData)

    def test_set_user_details_missing_field_username(self):
        requestData = {
            'masterPasswordAuthenticationHash': 'x',
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

    def test_set_user_details_missing_field_masterPasswordAuthenticationHash(self):
        requestData = {
            'username': 'alice',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
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
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        initialUserJson = createUserJson(alice)

        response = self.client.put('/userdetails', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}

        ## Be sure, nothing was changed
        assert createUserJson(User.query.get('alice')) == initialUserJson

    ## Unknown field test

    def test_set_user_details_unknown_field(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        initialUserJson = createUserJson(alice)

        userJson = createUserJson(alice)
        userJson['foo'] = 'bar'
        requestData = userJson
        response = self.client.put('/userdetails', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204

        ## Be sure, nothing was changed
        assert createUserJson(User.query.get('alice')) == initialUserJson

    ## Invalid JSON test

    def test_set_user_details_invalid_json(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        initialUserJson = createUserJson(alice)

        requestData = '{this is not valid JSON}'
        response = self.client.put('/userdetails', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}

        ## Be sure, nothing was changed
        assert createUserJson(User.query.get('alice')) == initialUserJson

    """
    Tests for GET /items

    """

    def test_get_user_items(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(
            Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901)
        )

        self.addItemAuthorizations(
            ItemAuthorization('itemAuthorization1', 'alice', 'item1', 'example item key 1', False, False, 12345678902, 12345678901)
        )

        response = self.client.get('/items', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))
        assert response.status_code == 200
        assert sortItemList(response.get_json()) == sortItemList([
            {'id': 'item1', 'userId': 'alice', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ])

    def test_get_user_items_with_deleted_item(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(
            Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901),
            Item('item2', 'alice', 'example data 2', True, 12345678902, 12345678901),
        )

        self.addItemAuthorizations(
            ItemAuthorization('itemAuthorization1', 'alice', 'item1', 'example item key 1', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization2', 'alice', 'item2', 'example item key 2', False, False, 12345678902, 12345678901)
        )

        response = self.client.get('/items', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200

        ## The "item2" is deleted, but is listed of course
        assert sortItemList(response.get_json()) == sortItemList([
            {'id': 'item1', 'userId': 'alice', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'id': 'item2', 'userId': 'alice', 'data': 'example data 2', 'deleted': True, 'modified': 12345678902, 'created': 12345678901}
        ])

    def test_get_user_items_without_any_item_authorization(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(
            Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901)
        )

        response = self.client.get('/items', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))
        assert response.status_code == 200

        ## Alice is not able to see "item1" because no item authorization exists
        assert sortItemList(response.get_json()) == sortItemList([])

    def test_get_user_items_without_shared_item_authorization(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(
            Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901),
            Item('item2', 'sandy', 'example data 2', False, 12345678902, 12345678901),
        )

        self.addItemAuthorizations(
            ItemAuthorization('itemAuthorization1', 'alice', 'item1', 'example item key 1', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization2', 'sandy', 'item2', 'example item key 2', False, False, 12345678902, 12345678901)
        )

        response = self.client.get('/items', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200

        ## Alice is only able to see "item1", because Sandy does not shared "item2" with her
        assert sortItemList(response.get_json()) == sortItemList([
            {'id': 'item1', 'userId': 'alice', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ])

    def test_get_user_items_with_shared_item_authorization(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(
            Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901),
            Item('item2', 'sandy', 'example data 2', False, 12345678902, 12345678901),
        )

        self.addItemAuthorizations(
            ItemAuthorization('itemAuthorization1', 'alice', 'item1', 'example item key 1', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization2', 'sandy', 'item2', 'example item key 2', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization3', 'alice', 'item2', 'example item key 2', False, False, 12345678902, 12345678901)
        )

        response = self.client.get('/items', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200

        ## The "item2" of Sandy is also accessible by Alice because she has a non-deleted item authorization
        assert sortItemList(response.get_json()) == sortItemList([
            {'id': 'item1', 'userId': 'alice', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'id': 'item2', 'userId': 'sandy', 'data': 'example data 2', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ])

    def test_get_user_items_with_deleted_shared_item_authorization(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(
            Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901),
            Item('item2', 'sandy', 'example data 2', False, 12345678902, 12345678901),
        )

        self.addItemAuthorizations(
            ItemAuthorization('itemAuthorization1', 'alice', 'item1', 'example item key 1', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization2', 'sandy', 'item2', 'example item key 2', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization3', 'alice', 'item2', 'example item key 2', False, True, 12345678902, 12345678901)
        )

        response = self.client.get('/items', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200

        ## The "item2" of Sandy is not accessible by Alice anymore because item authorization was deleted by Sandy
        assert sortItemList(response.get_json()) == sortItemList([
            {'id': 'item1', 'userId': 'alice', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ])

    """
    Tests for PUT /items

    """

    ## TODO

    """
    Tests for GET /itemauthorizations

    """

    def test_get_user_item_authorizations(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(
            Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901),
            Item('item2', 'alice', 'example data 2', False, 12345678902, 12345678901),
            Item('item3', 'sandy', 'example data 3', False, 12345678902, 12345678901)
        )

        self.addItemAuthorizations(
            ItemAuthorization('itemAuthorization1', 'alice', 'item1', 'example item key 1', False, False, 12345678902, 12345678901),

            ## Alice gave herself and Sandy access to "item2"
            ItemAuthorization('itemAuthorization2', 'alice', 'item2', 'example item key 2', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization3', 'sandy', 'item2', 'example item key 2', False, False, 12345678902, 12345678901),

            ## Sandy gave herself and Alice access to "item3" but deleted Alice item authorization
            ItemAuthorization('itemAuthorization4', 'sandy', 'item3', 'example item key 3', False, False, 12345678902, 12345678901),
            ItemAuthorization('itemAuthorization5', 'alice', 'item3', 'example item key 3', False, True, 12345678902, 12345678901)
        )

        response = self.client.get('/itemauthorizations', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200

        ## Alice see the item authorizations created from and for her (also the deleted ones)
        assert sortItemAuthorizationList(response.get_json()) == sortItemAuthorizationList([
            {'id': 'itemAuthorization1', 'userId': 'alice', 'itemId': 'item1', 'itemKey': 'example item key 1', 'readOnly': False, 'deleted': False, 'modified': 12345678902,'created': 12345678901},
            {'id': 'itemAuthorization2', 'userId': 'alice', 'itemId': 'item2', 'itemKey': 'example item key 2', 'readOnly': False, 'deleted': False, 'modified': 12345678902,'created': 12345678901},
            {'id': 'itemAuthorization3', 'userId': 'sandy', 'itemId': 'item2', 'itemKey': 'example item key 2', 'readOnly': False, 'deleted': False, 'modified': 12345678902,'created': 12345678901},
            {'id': 'itemAuthorization5', 'userId': 'alice', 'itemId': 'item3', 'itemKey': 'example item key 3', 'readOnly': False, 'deleted': True, 'modified': 12345678902,'created': 12345678901}
        ])

    """
    Tests for PUT /itemauthorizations

    """

    ## Create new item authorization tests

    def test_set_user_item_authorizations_create_authorizations(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(
            Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901),
            Item('item2', 'alice', 'example data 2', False, 12345678902, 12345678901)
        )

        itemAuthorization1Json = {
            'id': 'itemAuthorization1',
            'userId': 'alice',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        itemAuthorization2Json = {
            'id': 'itemAuthorization2',
            'userId': 'alice',
            'itemId': 'item2',
            'itemKey': 'example item key 2',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

        requestData = [itemAuthorization1Json, itemAuthorization2Json]
        response = self.client.put('/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == itemAuthorization1Json
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization2')) == itemAuthorization2Json

    def test_set_user_item_authorizations_create_deleted_authorization(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901))

        itemAuthorization1Json = {
            'id': 'itemAuthorization1',
            'userId': 'alice',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': True,
            'modified': 12345678902,
            'created': 12345678901
        }

        requestData = [itemAuthorization1Json]
        response = self.client.put('/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == itemAuthorization1Json

    def test_set_user_item_authorizations_create_authorization_with_not_existing_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901))

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
        response = self.client.put('/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 404
        assert response.get_json() == {'error': 'Not found'}
        assert ItemAuthorization.query.get('itemAuthorization1') == None

    def test_set_user_item_authorizations_create_authorization_with_not_existing_item(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901))

        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice',
            'itemId': 'notExistingItem',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        response = self.client.put('/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 404
        assert response.get_json() == {'error': 'Not found'}
        assert ItemAuthorization.query.get('itemAuthorization1') == None

    def test_set_user_item_authorizations_create_authorization_for_item_with_already_existing_item_authorization(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901))
        self.addItemAuthorizations(ItemAuthorization('itemAuthorization1', 'alice', 'item1', 'example item key 1', False, False, 12345678902, 12345678901))

        requestData = [{
            'id': 'itemAuthorization1a',
            'userId': 'alice',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        response = self.client.put('/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert ItemAuthorization.query.get('itemAuthorization1a') == None

    ## Permission tests

    def test_set_user_item_authorizations_create_authorization_for_item_is_owned_by_other_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(Item('item1', 'sandy', 'example data 1', False, 12345678902, 12345678901))

        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        response = self.client.put('/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        ## Alice is not allowed to create a item authorization for an item that is not owned by her
        assert response.status_code == 403
        assert response.get_json() == {'error': 'Forbidden'}
        assert ItemAuthorization.query.get('itemAuthorization1') == None

    def test_set_user_item_authorizations_update_authorization_for_item_is_owned_by_other_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(Item('item1', 'sandy', 'example data 1', False, 12345678902, 12345678901))
        self.addItemAuthorizations(ItemAuthorization('itemAuthorization1', 'alice', 'item1', 'example item key 1', True, False, 12345678902, 12345678901))

        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]
        response = self.client.put('/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        ## Alice is not allowed to change item authorization for her for an item that is not owned by her
        assert response.status_code == 403
        assert response.get_json() == {'error': 'Forbidden'}
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == {
            'id': 'itemAuthorization1',
            'userId': 'alice',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': True,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

    ## General modify field tests

    def test_set_user_item_authorizations_change_field_userId_existing(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'sandy',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]

        ## The field `userId` is immutable
        expected = {
            'id': 'itemAuthorization1',
            'userId': 'alice',
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

        ## The field `userId` is immutable
        expected = {
            'id': 'itemAuthorization1',
            'userId': 'alice',
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
            expectedStatusCode = 404,
            expectedResponseJson = {'error': 'Not found'}
        )

    def test_set_user_item_authorizations_change_field_itemId_existing(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice',
            'itemId': 'item2',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]

        ## The field `itemId` is immutable
        expected = {
            'id': 'itemAuthorization1',
            'userId': 'alice',
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
            'userId': 'alice',
            'itemId': 'notExistingItem',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]

        ## The field `itemId` is immutable
        expected = {
            'id': 'itemAuthorization1',
            'userId': 'alice',
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
            expectedStatusCode = 404,
            expectedResponseJson = {'error': 'Not found'}
        )

    def test_set_user_item_authorizations_change_field_itemKey(self):
        requestData = [{
            'id': 'itemAuthorization1',
            'userId': 'alice',
            'itemId': 'item1',
            'itemKey': 'example item key 1 changed',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }]

        ## The field `itemKey` is immutable
        expected = {
            'id': 'itemAuthorization1',
            'userId': 'alice',
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
            'userId': 'alice',
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
            'userId': 'alice',
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
            'userId': 'alice',
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
            'userId': 'alice',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678902
        }]

        ## The field `created` is immutable
        expected = {
            'id': 'itemAuthorization1',
            'userId': 'alice',
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
        expectedStatusCode = 204,
        expectedResponseJson = None
    ):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        self.addItems(
            Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901),
            Item('item2', 'alice', 'example data 2', False, 12345678902, 12345678901)
        )

        self.addItemAuthorizations(ItemAuthorization('itemAuthorization1', 'alice', 'item1', 'example item key 1', False, False, 12345678902, 12345678901))

        response = self.client.put('/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == expectedStatusCode
        assert response.get_json() == expectedResponseJson
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == expected

    ## General wrong field type tests

    def test_set_user_item_authorizations_wrong_field_type_id(self):
        requestData = [{
            'id': 1234,
            'userId': 'alice',
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
            'userId': 'alice',
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
            'userId': 'alice',
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
            'userId': 'alice',
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
            'userId': 'alice',
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
            'userId': 'alice',
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
            'userId': 'alice',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': False,
            'deleted': False,
            'modified': 12345678902,
            'created': 'this is not an integer'
        }]
        self.__test_set_user_item_authorizations_wrong_field_type(requestData)

    def __test_set_user_item_authorizations_wrong_field_type(self, requestData):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901))

        itemAuthorization1 = ItemAuthorization('itemAuthorization1', 'alice', 'item1', 'example item key 1', False, False, 12345678902, 12345678901)
        self.addItemAuthorizations(itemAuthorization1)

        initialItemAuthorization1Json = createItemAuthorizationJson(itemAuthorization1)

        response = self.client.put('/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}

        ## Be sure, nothing was changed
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == initialItemAuthorization1Json

    ## General missing field tests

    def test_set_user_item_authorizations_missing_field_all(self):
        requestData = [{}]
        self.__test_set_user_item_authorizations_missing_field(requestData)

    def test_set_user_item_authorizations_missing_field_id(self):
        requestData = [{
            'userId': 'alice',
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
            'userId': 'alice',
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
            'userId': 'alice',
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
            'userId': 'alice',
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
            'userId': 'alice',
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
            'userId': 'alice',
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
            'userId': 'alice',
            'itemId': 'item1',
            'itemKey': 'example item key 1',
            'readOnly': True,
            'deleted': True,
            'modified': 12345678902
        }]
        self.__test_set_user_item_authorizations_missing_field(requestData)

    def __test_set_user_item_authorizations_missing_field(self, requestData):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901))

        itemAuthorization1 = ItemAuthorization('itemAuthorization1', 'alice', 'item1', 'example item key 1', False, False, 12345678902, 12345678901)
        self.addItemAuthorizations(itemAuthorization1)

        initialItemAuthorization1Json = createItemAuthorizationJson(itemAuthorization1)

        response = self.client.put('/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}

        ## Be sure, nothing was changed
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == initialItemAuthorization1Json

    ## Unknown field test

    def test_set_user_item_authorizations_unknown_field(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901))

        itemAuthorization1 = ItemAuthorization('itemAuthorization1', 'alice', 'item1', 'example item key 1', False, False, 12345678902, 12345678901)
        self.addItemAuthorizations(itemAuthorization1)

        initialItemAuthorization1Json = createItemAuthorizationJson(itemAuthorization1)

        itemAuthorization1Json = createItemAuthorizationJson(itemAuthorization1)
        itemAuthorization1Json['foo'] = 'bar'
        requestData = [itemAuthorization1Json]
        response = self.client.put('/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204

        ## Be sure, nothing was changed
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == initialItemAuthorization1Json

    ## Invalid JSON test

    def test_set_user_item_authorizations_invalid_json(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901))

        itemAuthorization1 = ItemAuthorization('itemAuthorization1', 'alice', 'item1', 'example item key 1', False, False, 12345678902, 12345678901)
        self.addItemAuthorizations(itemAuthorization1)

        initialItemAuthorization1Json = createItemAuthorizationJson(itemAuthorization1)

        requestData = '[{this is not valid JSON]'
        response = self.client.put('/itemauthorizations', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}

        ## Be sure, nothing was changed
        assert createItemAuthorizationJson(ItemAuthorization.query.get('itemAuthorization1')) == initialItemAuthorization1Json

if __name__ == '__main__':
    unittest.main()
