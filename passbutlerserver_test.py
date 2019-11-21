#!/usr/bin/env python3

from flask_testing import TestCase
from passbutlerserver import createApp, db
from passbutlerserver import User
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

def createHttpBasicAuthHeaders(username, password):
    credentialBytes = (username + ':' + password).encode()
    base64EncodedCredentials = base64.b64encode(credentialBytes).decode('utf-8')
    return {'Authorization': 'Basic ' + base64EncodedCredentials}

def createHttpTokenAuthHeaders(secretKey, user, expiresIn=3600, signatureAlgorithm="HS512"):
    tokenSerializer = TimedJSONWebSignatureSerializer(secretKey, expires_in=expiresIn, algorithm_name=signatureAlgorithm)
    token = user.generateAuthenticationToken(tokenSerializer)
    return {'Authorization': 'Bearer ' + token}

def assertUserEquals(expectedUser, actualUser):
    if expectedUser is None or actualUser is None:
        raise AssertionError('The given user objects must not be None!')

    equalChecks = [
        expectedUser.username == actualUser.username,
        expectedUser.masterKeyDerivationInformation == actualUser.masterKeyDerivationInformation,
        expectedUser.masterEncryptionKey == actualUser.masterEncryptionKey,
        expectedUser.itemEncryptionPublicKey == actualUser.itemEncryptionPublicKey,
        expectedUser.itemEncryptionSecretKey == actualUser.itemEncryptionSecretKey,
        expectedUser.settings == actualUser.settings,
        expectedUser.deleted == actualUser.deleted,
        expectedUser.modified == actualUser.modified,
        expectedUser.created == actualUser.created
    ]

    if (all(equalChecks) == False):
        raise AssertionError('The user objects are not equal!')

class UserTests(PassButlerTestCase):

    def __add_users(self, *users):
        for user in users:
            db.session.add(user)

        db.session.commit()   

    """
    Tests for GET /token

    """

    def test_get_token_with_correct_credentials(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        response = self.client.get('/token', headers=createHttpBasicAuthHeaders('alice', '1234'))

        assert response.status_code == 200
        assert len(response.get_json().get('token')) == 181

    def test_get_token_with_invalid_credentials(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        response = self.client.get('/token', headers=createHttpBasicAuthHeaders('alice', '1235'))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_with_valid_token(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        response = self.client.get('/token', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        ## A token only can be requested with username and password
        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_without_authentication(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        response = self.client.get('/token')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_without_authentication_no_user_record(self):
        response = self.client.get('/token')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    """
    Tests for GET /users

    """

    def test_get_users_one_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        response = self.client.get('/users', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200
        assert response.get_json() == [
            {'username': 'alice', 'itemEncryptionPublicKey': 'a3', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ]

    def test_get_users_multiple_users(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678904, 12345678903)
        self.__add_users(alice, sandy)

        response = self.client.get('/users', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200
        assert response.get_json() == [
            {'username': 'alice', 'itemEncryptionPublicKey': 'a3', 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'username': 'sandy', 'itemEncryptionPublicKey': 's3', 'deleted': False, 'modified': 12345678904, 'created': 12345678903}
        ]

    """
    Authentication tests (using GET /user/username)

    """

    def test_get_user_without_authentication(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        response = self.client.get('/user/alice')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_without_authentication_no_user_record(self):
        response = self.client.get('/user/alice')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_unaccepted_password_authentication(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        response = self.client.get('/user/alice', headers=createHttpBasicAuthHeaders('alice', '1234'))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_expired_token(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        response = self.client.get('/user/alice', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice, -3600))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_token_without_signature(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        response = self.client.get('/user/alice', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice, signatureAlgorithm="none"))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}


    """
    Tests for GET /user/username

    """

    def test_get_user(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        response = self.client.get('/user/alice', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200

        aliceJson = createUserJson(alice)
        assert response.get_json() == aliceJson

    def test_get_user_as_other_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678904, 12345678903)
        self.__add_users(alice, sandy)

        ## Sandy is not allowed to access user details of Alice
        response = self.client.get('/user/alice', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, sandy))

        assert response.status_code == 403
        assert response.get_json() == {'error': 'Forbidden'}

    def test_get_nonexisting_user_as_other_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        response = self.client.get('/user/nonExistingUser', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 404
        assert response.get_json() == {'error': 'Not found'}

    """
    Tests for PUT /user/username

    """

    ## TODO: Add also authentication tests

    def test_update_user_one_field(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        ## Save user as JSON to be sure it is not connected to database
        aliceJson = createUserJson(alice)

        requestData = {'settings': 'a5a'}
        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        ## Discard uncommited changes to check if the changes has been committed
        db.session.rollback()

        assert response.status_code == 204

        ## Alter the JSON and compare users to be sure only the altered fields have changed
        aliceJson['settings'] = 'a5a'

        updatedAliceJson = createUserJson(User.query.get('alice'))

        assert aliceJson == updatedAliceJson

    def test_update_user_multiple_fields(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        aliceJson = createUserJson(alice)

        requestData = {'masterPasswordAuthenticationHash': 'x', 'masterEncryptionKey': 'a2a', 'settings': 'a5a', 'modified': 12345678903}
        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204

        aliceJson['masterPasswordAuthenticationHash'] = 'x'
        aliceJson['masterEncryptionKey'] = 'a2a'
        aliceJson['settings'] = 'a5a'
        aliceJson['modified'] = 12345678903

        updatedAliceJson = createUserJson(User.query.get('alice'))

        assert aliceJson == updatedAliceJson

    def test_update_user_unknown_field(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        aliceJson = createUserJson(alice)

        requestData = {'foo': 'bar'}
        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204

        ## Nothing is changed
        updatedAliceJson = createUserJson(User.query.get('alice'))
        assert aliceJson == updatedAliceJson

    def test_update_user_immutable_field(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        aliceJson = createUserJson(alice)

        requestData = {'created': 12345678902}
        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204

        ## Nothing is changed
        updatedAliceJson = createUserJson(User.query.get('alice'))
        assert aliceJson == updatedAliceJson

    def test_update_user_wrong_json_type(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__add_users(alice)

        aliceJson = createUserJson(alice)

        requestData = aliceJson.copy()

        ## Change a value to invalid type
        requestData['modified'] = 'a'

        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}

        updatedAliceJson = createUserJson(User.query.get('alice'))
        assert aliceJson == updatedAliceJson

if __name__ == '__main__':
    unittest.main()
