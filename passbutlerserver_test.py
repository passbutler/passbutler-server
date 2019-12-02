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

    """
    Tests for GET /users

    """

    def test_get_users_one_user(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        response = self.client.get('/users', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200
        assert response.get_json() == [
            {'username': 'alice', 'itemEncryptionPublicKey': 'a3', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ]

    def test_get_users_multiple_users(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678904, 12345678903)
        self.addUsers(alice, sandy)

        response = self.client.get('/users', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200
        assert response.get_json() == [
            {'username': 'alice', 'itemEncryptionPublicKey': 'a3', 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'username': 'sandy', 'itemEncryptionPublicKey': 's3', 'deleted': False, 'modified': 12345678904, 'created': 12345678903}
        ]

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
    Tests for PUT /user/username

    """

    def test_update_user_one_field(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        requestData = {'settings': 'a5a'}
        response = self.client.put('/userdetails', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        ## Discard uncommited changes to check if the changes has been committed
        db.session.rollback()

        assert response.status_code == 204
        assert createUserJson(User.query.get('alice')) == {
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'x',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5a',
            'deleted': False,
            'modified': 12345678902,
            'created': 12345678901
        }

    def test_update_user_multiple_fields(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        requestData = {'masterPasswordAuthenticationHash': 'xa', 'masterEncryptionKey': 'a2a', 'settings': 'a5a', 'modified': 12345678903}
        response = self.client.put('/userdetails', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204
        assert createUserJson(User.query.get('alice')) == {
            'username': 'alice',
            'masterPasswordAuthenticationHash': 'xa',
            'masterKeyDerivationInformation': 'a1',
            'masterEncryptionKey': 'a2a',
            'itemEncryptionPublicKey': 'a3',
            'itemEncryptionSecretKey': 'a4',
            'settings': 'a5a',
            'deleted': False,
            'modified': 12345678903,
            'created': 12345678901
        }

    def test_update_user_unknown_field(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        requestData = {'foo': 'bar'}
        response = self.client.put('/userdetails', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204
        assert createUserJson(User.query.get('alice')) == {
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

    def test_update_user_immutable_field(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        requestData = {'created': 12345678902}
        response = self.client.put('/userdetails', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 204
        assert createUserJson(User.query.get('alice')) == {
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

    def test_update_user_wrong_json_type(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        requestData = {'modified': 'this is not an integer timestamp'}
        response = self.client.put('/userdetails', json=requestData, headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        db.session.rollback()

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}
        assert createUserJson(User.query.get('alice')) == {
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
        assert response.get_json() == [
            {'id': 'item1', 'userId': 'alice', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ]

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
        assert response.get_json() == [
            {'id': 'item1', 'userId': 'alice', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'id': 'item2', 'userId': 'alice', 'data': 'example data 2', 'deleted': True, 'modified': 12345678902, 'created': 12345678901}
        ]

    def test_get_user_items_without_any_item_authorization(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        self.addUsers(alice)

        self.addItems(
            Item('item1', 'alice', 'example data 1', False, 12345678902, 12345678901)
        )

        response = self.client.get('/items', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))
        assert response.status_code == 200

        ## Alice is not able to see "item1" because no item authorization exists
        assert response.get_json() == []

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
        assert response.get_json() == [
            {'id': 'item1', 'userId': 'alice', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ]

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
        assert response.get_json() == [
            {'id': 'item1', 'userId': 'alice', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'id': 'item2', 'userId': 'sandy', 'data': 'example data 2', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ]

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
        assert response.get_json() == [
            {'id': 'item1', 'userId': 'alice', 'data': 'example data 1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ]

    """
    Tests for GET /itemauthorizations

    """

    def test_get_user_item_authorizations(self):
        alice = User('alice', 'x', 'a1', 'a2', 'a3', 'a4', 'a5', False, 12345678902, 12345678901)
        sandy = User('sandy', 'y', 's1', 's2', 's3', 's4', 's5', False, 12345678902, 12345678901)
        self.addUsers(alice, sandy)

        itemAuthorization1 = ItemAuthorization('itemAuthorization1', 'alice', 'item1', 'example item key 1', False, False, 12345678902, 12345678901)
        itemAuthorization2 = ItemAuthorization('itemAuthorization2', 'alice', 'item2', 'example item key 2', True, False, 12345678902, 12345678901)
        itemAuthorization3 = ItemAuthorization('itemAuthorization3', 'alice', 'item3', 'example item key 3', True, True, 12345678902, 12345678901)
        itemAuthorization4 = ItemAuthorization('itemAuthorization4', 'sandy', 'item2', 'example item key 2', False, False, 12345678902, 12345678901)
        self.addItemAuthorizations(itemAuthorization1, itemAuthorization2, itemAuthorization3, itemAuthorization4)

        response = self.client.get('/itemauthorizations', headers=createHttpTokenAuthHeaders(self.SECRET_KEY, alice))

        assert response.status_code == 200

        ## Alice see only her own item authorizations (also the deleted ones)
        assert response.get_json() == [
            {'id': 'itemAuthorization1', 'userId': 'alice', 'itemId': 'item1', 'itemKey': 'example item key 1', 'readOnly': False, 'deleted': False, 'modified': 12345678902,'created': 12345678901},
            {'id': 'itemAuthorization2', 'userId': 'alice', 'itemId': 'item2', 'itemKey': 'example item key 2', 'readOnly': True, 'deleted': False, 'modified': 12345678902,'created': 12345678901},
            {'id': 'itemAuthorization3', 'userId': 'alice', 'itemId': 'item3', 'itemKey': 'example item key 3', 'readOnly': True, 'deleted': True, 'modified': 12345678902,'created': 12345678901},
        ]

if __name__ == '__main__':
    unittest.main()
