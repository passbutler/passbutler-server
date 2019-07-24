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

def createHttpTokenAuthHeaders(secretKey, user, expiresIn=3600):
    tokenSerializer = TimedJSONWebSignatureSerializer(secretKey, expires_in=expiresIn)
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

    """
    Tests for GET /token

    """

    def test_get_token_with_correct_credentials(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(alice)
        db.session.commit()

        response = self.client.get('/token', headers=createHttpBasicAuthHeaders('alice', '1234'))

        assert response.status_code == 200
        assert len(response.get_json().get('token')) == 181

    def test_get_token_with_invalid_credentials(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(alice)
        db.session.commit()

        response = self.client.get('/token', headers=createHttpBasicAuthHeaders('alice', '1235'))

        assert response.status_code == 403
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_with_valid_token(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(alice)
        db.session.commit()

        response = self.client.get('/token', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        ## A token only can be requested with username and password
        assert response.status_code == 403
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_without_authentication(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(alice)
        db.session.commit()

        response = self.client.get('/token')

        assert response.status_code == 403
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_without_authentication_no_user_record(self):
        response = self.client.get('/token')

        assert response.status_code == 403
        assert response.get_json() == {'error': 'Unauthorized'}

    """
    Tests for GET /users

    """

    def test_get_users_no_users(self):
        response = self.client.get('/users')

        assert response.status_code == 200
        assert b'[]' in response.data

    def test_get_users_one_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(alice)
        db.session.commit()

        response = self.client.get('/users')

        assert response.status_code == 200
        assert response.get_json() == [
            {'username': 'alice', 'itemEncryptionPublicKey': 'a3', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ]

    def test_get_users_multiple_users(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(alice)

        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678904, 12345678903)
        db.session.add(sandy)

        db.session.commit()

        response = self.client.get('/users')

        assert response.status_code == 200
        assert response.get_json() == [
            {'username': 'alice', 'itemEncryptionPublicKey': 'a3', 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'username': 'sandy', 'itemEncryptionPublicKey': 's3', 'deleted': False, 'modified': 12345678904, 'created': 12345678903}
        ]

    """
    Tests for POST /users

    """

    def test_create_users_one_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        aliceJson = createUserJson(alice)

        requestData = [aliceJson]
        response = self.client.post('/users', json=requestData)

        assert response.status_code == 204

        actualAlice = User.query.get('alice')
        assertUserEquals(alice, actualAlice)

    def test_create_users_multiple_users(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        aliceJson = createUserJson(alice)

        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678904, 12345678903)
        sandyJson = createUserJson(sandy)

        requestData = [aliceJson, sandyJson]
        response = self.client.post('/users', json=requestData)

        assert response.status_code == 204

        actualAlice = User.query.get('alice')
        assertUserEquals(alice, actualAlice)

        actualSandy = User.query.get('sandy')
        assertUserEquals(sandy, actualSandy)

    def test_create_users_already_existing(self):
        initialUser = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(initialUser)
        db.session.commit()

        addingUser = User('alice', 'x', 'b1', 'b2', 'b3', 'b4', 'b5', False, 12345678904, 12345678903)
        addingUserJson = createUserJson(addingUser)

        requestData = [addingUserJson]
        response = self.client.post('/users', json=requestData)

        assert response.status_code == 409
        assert response.get_json() == {'error': 'Already exists'}

        ## Check that the initial existing user is unchanged
        existingUser = User.query.get('alice')
        assertUserEquals(initialUser, existingUser)

    def test_create_users_missing_json_key(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        aliceJson = createUserJson(alice)

        ## Remove value
        del aliceJson['settings']

        requestData = [aliceJson]
        response = self.client.post('/users', json=requestData)

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}

        createdUser = User.query.get(alice.username)
        assert createdUser == None

    def test_create_users_wrong_json_type(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        aliceJson = createUserJson(alice)

        ## Change a value to invalid type
        aliceJson['modified'] = 'a'

        requestData = [aliceJson]
        response = self.client.post('/users', json=requestData)
        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}

        createdUser = User.query.get(alice.username)
        assert createdUser == None

    """
    Tests for GET /user/username (include authentication tests)

    """

    def test_get_user(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(alice)
        db.session.commit()

        response = self.client.get('/user/alice', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200

        aliceJson = createUserJson(alice)
        assert response.get_json() == aliceJson

    def test_get_user_as_unauthorized_user(self):
        response = self.client.get('/user/nonExistingUser')

        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(alice)

        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678904, 12345678903)
        db.session.add(sandy)

        ## Sandy is not allowed to access user details of alice
        response = self.client.get('/user/alice', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, sandy))

        assert response.status_code == 403
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_without_authentication(self):
        user = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(user)
        db.session.commit()

        response = self.client.get('/user/alice')

        assert response.status_code == 403
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_without_authentication_no_user_record(self):
        response = self.client.get('/user/alice')

        assert response.status_code == 403
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_unaccepted_password_authentication(self):
        user = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(user)
        db.session.commit()

        response = self.client.get('/user/alice', headers=createHttpBasicAuthHeaders('alice', '1234'))

        assert response.status_code == 403
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_expired_token(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(alice)
        db.session.commit()

        response = self.client.get('/user/alice', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice, -3600))

        assert response.status_code == 403
        assert response.get_json() == {'error': 'Unauthorized'}

    """
    Tests for PUT /user/username

    """

    def test_update_user_one_field(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(alice)
        db.session.commit()

        ## Save user as JSON to be sure it is not connected to database
        aliceJson = createUserJson(alice)

        requestData = {'settings': 'a5a'}
        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 204

        ## Alter the JSON and compare users to be sure only the altered fields have changed
        aliceJson['settings'] = 'a5a'

        updatedAliceJson = createUserJson(User.query.get('alice'))

        assert aliceJson == updatedAliceJson

    def test_update_user_multiple_fields(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(alice)
        db.session.commit()

        aliceJson = createUserJson(alice)

        requestData = {'masterPasswordAuthenticationHash': 'x', 'masterEncryptionKey': 'a2a', 'settings': 'a5a', 'modified': 12345678903}
        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 204

        aliceJson['masterPasswordAuthenticationHash'] = 'x'
        aliceJson['masterEncryptionKey'] = 'a2a'
        aliceJson['settings'] = 'a5a'
        aliceJson['modified'] = 12345678903

        updatedAliceJson = createUserJson(User.query.get('alice'))

        assert aliceJson == updatedAliceJson

    def test_update_user_unknown_field(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(alice)
        db.session.commit()

        aliceJson = createUserJson(alice)

        requestData = {'foo': 'bar'}
        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 204

        ## Nothing is changed
        updatedAliceJson = createUserJson(User.query.get('alice'))
        assert aliceJson == updatedAliceJson

    def test_update_user_immutable_field(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(alice)
        db.session.commit()

        aliceJson = createUserJson(alice)

        requestData = {'created': 12345678902}
        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 204

        ## Nothing is changed
        updatedAliceJson = createUserJson(User.query.get('alice'))
        assert aliceJson == updatedAliceJson

    def test_update_user_wrong_json_type(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        db.session.add(alice)
        db.session.commit()

        aliceJson = createUserJson(alice)

        requestData = aliceJson.copy()

        ## Change a value to invalid type
        requestData['modified'] = 'a'

        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}

        updatedAliceJson = createUserJson(User.query.get('alice'))
        assert aliceJson == updatedAliceJson

if __name__ == '__main__':
    unittest.main()
