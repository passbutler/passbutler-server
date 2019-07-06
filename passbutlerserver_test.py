#!/usr/bin/env python3

import unittest
from flask_testing import TestCase
from passbutlerserver import createApp, db
from passbutlerserver import User

class PassButlerTestCase(TestCase):

    TESTING = True

    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SECRET_KEY = 'secretKeyForTesting'

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
        user = User("testuser", "a", "b", "c", "d", "e", False, 12345678902, 12345678901)
        db.session.add(user)
        db.session.commit()

        response = self.client.get("/users")

        assert response.status_code == 200
        assert response.get_json() == [
            {'username': 'testuser', 'itemEncryptionPublicKey': 'c', 'deleted': False, 'modified': 12345678902, 'created': 12345678901}
        ]

    def test_get_users_multiple_users(self):
        user1 = User("testuser1", "a1", "b1", "c1", "d1", "e1", False, 12345678902, 12345678901)
        db.session.add(user1)

        user2 = User("testuser2", "a2", "b2", "c2", "d2", "e2", False, 12345678904, 12345678903)
        db.session.add(user2)

        db.session.commit()

        response = self.client.get("/users")

        assert response.status_code == 200
        assert response.get_json() == [
            {'username': 'testuser1', 'itemEncryptionPublicKey': 'c1', 'deleted': False, 'modified': 12345678902, 'created': 12345678901},
            {'username': 'testuser2', 'itemEncryptionPublicKey': 'c2', 'deleted': False, 'modified': 12345678904, 'created': 12345678903}
        ]

    """
    Tests for POST /users

    """

    def test_create_users_one_user(self):
        newUser = User("testuser", "a", "b", "c", "d", "e", False, 12345678902, 12345678901)
        newUserJson = createUserJson(newUser)
        response = self.client.post("/users", json=[newUserJson])

        assert response.status_code == 204

        actualUser = User.query.get("testuser")
        assertUserEquals(newUser, actualUser)

    def test_create_users_multiple_users(self):
        newUser1 = User("testuser1", "a1", "b1", "c1", "d1", "e1", False, 12345678902, 12345678901)
        newUser1Json = createUserJson(newUser1)

        newUser2 = User("testuser2", "a2", "b2", "c2", "d2", "e2", False, 12345678904, 12345678903)
        newUser2Json = createUserJson(newUser2)

        response = self.client.post("/users", json=[newUser1Json, newUser2Json])

        assert response.status_code == 204

        actualNewUser1 = User.query.get("testuser1")
        assertUserEquals(newUser1, actualNewUser1)

        actualNewUser2 = User.query.get("testuser2")
        assertUserEquals(newUser2, actualNewUser2)

    def test_create_users_already_existing(self):
        initialExistingUser = User("testuser", "a1", "b1", "c1", "d1", "e1", False, 12345678902, 12345678901)
        db.session.add(initialExistingUser)
        db.session.commit()

        addingUser = User("testuser", "a2", "b2", "c2", "d2", "e2", False, 12345678904, 12345678903)
        addingUserJson = createUserJson(addingUser)
        response = self.client.post("/users", json=[addingUserJson])

        assert response.status_code == 409
        assert response.get_json() == {'error': 'Already exists'}

        ## Check that the initial existing user is unchanged
        existingUser = User.query.get("testuser")
        assertUserEquals(initialExistingUser, existingUser)

    def test_create_users_missing_json_key(self):
        newUser = User("testuser", "a", "b", "c", "d", "e", False, 12345678902, 12345678901)
        newUserJson = createUserJson(newUser)

        ## Remove key
        del newUserJson["settings"]

        response = self.client.post("/users", json=[newUserJson])

        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}

        createdUser = User.query.get("testuser")
        assert createdUser == None

    def test_create_users_wrong_json_key_type(self):
        newUser = User("testuser", "a", "b", "c", "d", "e", False, 12345678902, 12345678901)
        newUserJson = createUserJson(newUser)

        ## Change key type to integer
        newUserJson["settings"] = 123

        response = self.client.post("/users", json=[newUserJson])
        assert response.status_code == 400
        assert response.get_json() == {'error': 'Invalid request'}

        createdUser = User.query.get("testuser")
        assert createdUser == None

    """
    Tests for GET /user/exampleuser

    """

    ## TODO: Authentication
    def test_get_user(self):
        user = User("testuser", "a", "b", "c", "d", "e", False, 12345678902, 12345678901)
        db.session.add(user)
        db.session.commit()

        response = self.client.get("/user/testuser")

        assert response.status_code == 200

        userJson = createUserJson(user)
        assert response.get_json() == userJson

    def test_get_user_not_existing(self):
        response = self.client.get("/user/nonExistingUser")

        assert response.status_code == 404
        assert response.get_json() == {'error': 'Not found'}

if __name__ == '__main__':
    unittest.main()
