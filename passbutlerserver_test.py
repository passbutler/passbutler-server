#!/usr/bin/env python3

import unittest
from flask_testing import TestCase
from passbutlerserver import createApp, db
from passbutlerserver import User

class PassButlerTestCase(TestCase):

    TESTING = True

    SQLALCHEMY_DATABASE_URI = "sqlite://"
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
        "username": user.username,
        "authenticationPasswordHash": user.authenticationPasswordHash,
        "masterKeyDerivationInformation": user.masterKeyDerivationInformation,
        "masterEncryptionKey": user.masterEncryptionKey,
        "itemEncryptionPublicKey": user.itemEncryptionPublicKey,
        "itemEncryptionSecretKey": user.itemEncryptionSecretKey,
        "settings": user.settings,
        "deleted": user.deleted,
        "modified": user.modified,
        "created": user.created
    }

def assertUserEquals(expectedUser, actualUser):
    if expectedUser is None or actualUser is None:
        raise AssertionError("The given user objects must not be None!")

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
        raise AssertionError("The user objects are not equal!")

class UserTests(PassButlerTestCase):

    """
    Tests for GET /users

    """

    def test_get_users_no_users(self):
        response = self.client.get("/users")

        assert response.status_code == 200
        assert b'[]' in response.data

    def test_get_users_one_user(self):
        alice = User("alice", "x", "a1", "a2", "a3", "a4", "a5", False, 12345678902, 12345678901)
        db.session.add(alice)
        db.session.commit()

        response = self.client.get("/users")

        assert response.status_code == 200
        assert response.get_json() == [
            {'username': 'alice', 'itemEncryptionPublicKey': 'a3', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ]

    def test_get_users_multiple_users(self):
        alice = User("alice", "x", "a1", "a2", "a3", "a4", "a5", False, 12345678902, 12345678901)
        db.session.add(alice)

        sandy = User("sandy", "y", "s1", "s2", "s3", "s4", "s5", False, 12345678904, 12345678903)
        db.session.add(sandy)

        db.session.commit()

        response = self.client.get("/users")

        assert response.status_code == 200
        assert response.get_json() == [
            {'username': 'alice', 'itemEncryptionPublicKey': 'a3', 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'username': 'sandy', 'itemEncryptionPublicKey': 's3', 'deleted': False, 'modified': 12345678904, 'created': 12345678903}
        ]

    """
    Tests for POST /users

    """

    def test_create_users_one_user(self):
        alice = User("alice", "x", "a1", "a2", "a3", "a4", "a5", False, 12345678902, 12345678901)
        aliceJson = createUserJson(alice)
        response = self.client.post("/users", json=[aliceJson])

        assert response.status_code == 204

        actualAlice = User.query.get("alice")
        assertUserEquals(alice, actualAlice)

    def test_create_users_multiple_users(self):
        alice = User("alice", "x", "a1", "a2", "a3", "a4", "a5", False, 12345678902, 12345678901)
        aliceJson = createUserJson(alice)

        sandy = User("sandy", "y", "s1", "s2", "s3", "s4", "s5", False, 12345678904, 12345678903)
        sandyJson = createUserJson(sandy)

        response = self.client.post("/users", json=[aliceJson, sandyJson])

        assert response.status_code == 204

        actualAlice = User.query.get("alice")
        assertUserEquals(alice, actualAlice)

        actualSandy = User.query.get("sandy")
        assertUserEquals(sandy, actualSandy)

    def test_create_users_already_existing(self):
        initialUser = User("alice", "x", "a1", "a2", "a3", "a4", "a5", False, 12345678902, 12345678901)
        db.session.add(initialUser)
        db.session.commit()

        addingUser = User("alice", "x", "b1", "b2", "b3", "b4", "b5", False, 12345678904, 12345678903)
        addingUserJson = createUserJson(addingUser)
        response = self.client.post("/users", json=[addingUserJson])

        assert response.status_code == 409
        assert response.get_json() == {'error': 'Already exists'}

        ## Check that the initial existing user is unchanged
        existingUser = User.query.get("alice")
        assertUserEquals(initialUser, existingUser)

    def test_create_users_missing_json_key(self):
        alice = User("alice", "x", "a1", "a2", "a3", "a4", "a5", False, 12345678902, 12345678901)
        aliceJson = createUserJson(alice)

        ## Remove key
        del aliceJson["settings"]

        response = self.client.post("/users", json=[aliceJson])

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}

        createdUser = User.query.get(alice.username)
        assert createdUser == None

    def test_create_users_wrong_json_key_type(self):
        alice = User("alice", "x", "a1", "a2", "a3", "a4", "a5", False, 12345678902, 12345678901)
        aliceJson = createUserJson(alice)

        ## Change key type to integer
        aliceJson["settings"] = 123

        response = self.client.post("/users", json=[aliceJson])
        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}

        createdUser = User.query.get(alice.username)
        assert createdUser == None

    """
    Tests for GET /user/username

    """

    ## TODO: Authentication + only own user + token tests
    def test_get_user(self):
        user = User("alice", "x", "a1", "a2", "a3", "a4", "a5", False, 12345678902, 12345678901)
        db.session.add(user)
        db.session.commit()

        response = self.client.get("/user/alice")

        assert response.status_code == 200

        userJson = createUserJson(user)
        assert response.get_json() == userJson

    def test_get_user_not_existing(self):
        response = self.client.get("/user/nonExistingUser")

        assert response.status_code == 404
        assert response.get_json() == {'error': 'Not found'}

if __name__ == '__main__':
    unittest.main()
