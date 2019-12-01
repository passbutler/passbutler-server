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

    def __addUsers(self, *users):
        for user in users:
            db.session.add(user)

        db.session.commit()   

    def __addItems(self, *items):
        for item in items:
            db.session.add(item)

        db.session.commit()  

    def __addItemAuthorizations(self, *itemAuthorizations):
        for itemAuthorization in itemAuthorizations:
            db.session.add(itemAuthorization)

        db.session.commit() 

    """
    Tests for GET /token

    """

    def test_get_token_with_correct_credentials(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        response = self.client.get('/token', headers=createHttpBasicAuthHeaders('alice', '1234'))

        assert response.status_code == 200
        assert len(response.get_json().get('token')) == 181

    def test_get_token_with_invalid_credentials(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        response = self.client.get('/token', headers=createHttpBasicAuthHeaders('alice', '1235'))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_with_valid_token(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        response = self.client.get('/token', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        ## A token only can be requested with username and password
        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_without_authentication(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        response = self.client.get('/token')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_token_without_authentication_no_user_record(self):
        response = self.client.get('/token')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    """
    Authentication tests (using GET /user/username)

    """

    def test_get_user_details_without_authentication(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        response = self.client.get('/user/alice')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_details_without_authentication_no_user_record(self):
        response = self.client.get('/user/alice')

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_details_unaccepted_password_authentication(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        response = self.client.get('/user/alice', headers=createHttpBasicAuthHeaders('alice', '1234'))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_details_expired_token(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        response = self.client.get('/user/alice', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice, -3600))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    def test_get_user_details_token_without_signature(self):
        alice = User('alice', 'pbkdf2:sha256:150000$BOV4dvoc$333626f4403cf4f7ab627824cf0643e0e9937335d6600154ac154860f09a2309', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        response = self.client.get('/user/alice', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice, signatureAlgorithm="none"))

        assert response.status_code == 401
        assert response.get_json() == {'error': 'Unauthorized'}

    """
    Tests for GET /users

    """

    def test_get_users_one_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        response = self.client.get('/users', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200
        assert response.get_json() == [
            {'username': 'alice', 'itemEncryptionPublicKey': 'a3', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ]

    def test_get_users_multiple_users(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678904, 12345678903)
        self.__addUsers(alice, sandy)

        response = self.client.get('/users', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200
        assert response.get_json() == [
            {'username': 'alice', 'itemEncryptionPublicKey': 'a3', 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'username': 'sandy', 'itemEncryptionPublicKey': 's3', 'deleted': False, 'modified': 12345678904, 'created': 12345678903}
        ]

    """
    Tests for GET /user/username

    """

    def test_get_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        response = self.client.get('/user/alice', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200

        aliceJson = createUserJson(alice)
        assert response.get_json() == aliceJson

    def test_get_user_details_as_other_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678904, 12345678903)
        self.__addUsers(alice, sandy)

        ## Sandy is not allowed to access user details of Alice
        response = self.client.get('/user/alice', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, sandy))

        assert response.status_code == 403
        assert response.get_json() == {'error': 'Forbidden'}

    def test_get_nonexisting_user_as_other_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        response = self.client.get('/user/nonExistingUser', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 404
        assert response.get_json() == {'error': 'Not found'}

    """
    Tests for PUT /user/username

    """

    def test_update_user_one_field(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        ## Save user as JSON to be sure it is not connected to database
        aliceJsonBefore = createUserJson(alice)

        requestData = {'settings': 'a5a'}
        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        ## Discard uncommited changes to check if the changes has been committed
        db.session.rollback()

        assert response.status_code == 204

        ## Alter the JSON and compare users to be sure only the altered fields have changed
        aliceJsonBefore['settings'] = 'a5a'

        aliceJsonAfter = createUserJson(User.query.get('alice'))

        assert aliceJsonBefore == aliceJsonAfter

    def test_update_user_multiple_fields(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        aliceJsonBefore = createUserJson(alice)

        requestData = {'masterPasswordAuthenticationHash': 'x', 'masterEncryptionKey': 'a2a', 'settings': 'a5a', 'modified': 12345678903}
        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204

        aliceJsonBefore['masterPasswordAuthenticationHash'] = 'x'
        aliceJsonBefore['masterEncryptionKey'] = 'a2a'
        aliceJsonBefore['settings'] = 'a5a'
        aliceJsonBefore['modified'] = 12345678903

        aliceJsonAfter = createUserJson(User.query.get('alice'))

        assert aliceJsonBefore == aliceJsonAfter

    def test_update_user_as_other_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678904, 12345678903)
        self.__addUsers(alice, sandy)

        aliceJsonBefore = createUserJson(alice)

        ## Sandy is not allowed to update user details of Alice
        requestData = {'settings': 'a5a'}
        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, sandy))

        db.session.rollback()

        assert response.status_code == 403
        assert response.get_json() == {'error': 'Forbidden'}

        aliceJsonAfter = createUserJson(User.query.get('alice'))

        assert aliceJsonBefore == aliceJsonAfter

    def test_update_nonexisting_user_as_other_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        requestData = {'settings': 'foobar'}
        response = self.client.put('/user/nonExistingUser', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 404
        assert response.get_json() == {'error': 'Not found'}

    def test_update_user_unknown_field(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        aliceJsonBefore = createUserJson(alice)

        requestData = {'foo': 'bar'}
        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204

        aliceJsonAfter = createUserJson(User.query.get('alice'))
        assert aliceJsonBefore == aliceJsonAfter

    def test_update_user_immutable_field(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        aliceJsonBefore = createUserJson(alice)

        requestData = {'created': 12345678902}
        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204

        aliceJsonAfter = createUserJson(User.query.get('alice'))
        assert aliceJsonBefore == aliceJsonAfter

    def test_update_user_wrong_json_type(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        aliceJsonBefore = createUserJson(alice)

        requestData = {'modified': 'a'}
        response = self.client.put('/user/alice', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}

        aliceJsonAfter = createUserJson(User.query.get('alice'))
        assert aliceJsonBefore == aliceJsonAfter

    """
    Tests for GET /user/username/items

    """

    def test_get_user_items(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.__addUsers(alice)

        self.__addItems(
            Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901),
            Item('item2', 'alice', 'example data 2', True, 12345678904, 12345678903),
        )

        response = self.client.get('/user/alice/items', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200
        assert response.get_json() == [
            {'id': 'item1', 'userId': 'alice', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'id': 'item2', 'userId': 'alice', 'data': 'example data 2', 'deleted': True, 'modified': 12345678904, 'created': 12345678903}
        ]

    """
    Tests for GET /user/username/itemauthorizations

    """

    def test_get_user_item_authorizations(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.__addUsers(alice, sandy)

        item1 = Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901)
        item2 = Item('item2', 'sandy', 'example data 2', False, 12345678902, 12345678901)
        item3 = Item('item3', 'sandy', 'example data 3', False, 12345678902, 12345678901)
        self.__addItems(item1, item2, item3)

        ## Item authorization for "alice" for her item
        itemAuthorization1 = ItemAuthorization('itemAuthorization1', 'alice', 'item1', 'example item key 1', False, False, 12345678902, 12345678901)

        ## Item authorization (readonly) for "alice" for item of "sandy"
        itemAuthorization2 = ItemAuthorization('itemAuthorization2', 'alice', 'item2', 'example item key 2', True, False, 12345678902, 12345678901)

        ## Item authorization (readonly and deleted) for "alice" for item of "sandy"
        itemAuthorization3 = ItemAuthorization('itemAuthorization3', 'alice', 'item3', 'example item key 3', True, True, 12345678902, 12345678901)

        ## Item authorization for "sandy" for her item
        itemAuthorization4 = ItemAuthorization('itemAuthorization4', 'sandy', 'item2', 'example item key 2', False, False, 12345678902, 12345678901)

        self.__addItemAuthorizations(itemAuthorization1, itemAuthorization2, itemAuthorization3, itemAuthorization4)

        response = self.client.get('/user/alice/itemauthorizations', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200
        assert response.get_json() == [
            {'id': 'itemAuthorization1', 'userId': 'alice', 'itemId': 'item1', 'itemKey': 'example item key 1', 'readOnly': False, 'deleted': False, 'modified': 12345678902,'created': 12345678901},
            {'id': 'itemAuthorization2', 'userId': 'alice', 'itemId': 'item2', 'itemKey': 'example item key 2', 'readOnly': True, 'deleted': False, 'modified': 12345678902,'created': 12345678901},
            {'id': 'itemAuthorization3', 'userId': 'alice', 'itemId': 'item3', 'itemKey': 'example item key 3', 'readOnly': True, 'deleted': True, 'modified': 12345678902,'created': 12345678901},
        ]

if __name__ == '__main__':
    unittest.main()
