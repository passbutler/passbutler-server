from flask_testing import TestCase
from passbutlerserver import create_app, db
from passbutlerserver import User

class PassButlerTestCase(TestCase):

    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TESTING = True

    def create_app(self):
        app = create_app(self)
        return app

    def setUp(self):
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

class UserTests(PassButlerTestCase):

    # def test_get_users_no_users(self):
    #     response = self.client.get("/users")

    #     assert response.status_code == 200
    #     assert b'[]' in response.data

    # def test_get_users_one_user(self):
    #     user = User(
    #         username = "testuser",
    #         masterKeyDerivationInformation = "a",
    #         masterEncryptionKey = "b",
    #         itemEncryptionPublicKey = "c",
    #         itemEncryptionSecretKey = "d",
    #         settings = "e",
    #         deleted = False,
    #         modified = 12345678902,
    #         created = 12345678901
    #     )

    #     db.session.add(user)
    #     db.session.commit()

    #     response = self.client.get("/users")

    #     assert response.status_code == 200
    #     assert response.get_json() == [{
    #         'username': 'testuser',
    #         'itemEncryptionPublicKey': 'c',
    #         'deleted': False,
    #         'modified': 12345678902,
    #         'created': 12345678901,
    #     }]

    # def test_get_users_multiple_users(self):
    #     user1 = User(
    #         username = "testuser1",
    #         masterKeyDerivationInformation = "a1",
    #         masterEncryptionKey = "b1",
    #         itemEncryptionPublicKey = "c1",
    #         itemEncryptionSecretKey = "d1",
    #         settings = "e1",
    #         deleted = False,
    #         modified = 12345678902,
    #         created = 12345678901
    #     )
    #     db.session.add(user1)

    #     user2 = User(
    #         username = "testuser2",
    #         masterKeyDerivationInformation = "a2",
    #         masterEncryptionKey = "b2",
    #         itemEncryptionPublicKey = "c2",
    #         itemEncryptionSecretKey = "d2",
    #         settings = "e2",
    #         deleted = False,
    #         modified = 12345678903,
    #         created = 12345678902
    #     )
    #     db.session.add(user2)

    #     db.session.commit()

    #     response = self.client.get("/users")

    #     assert response.status_code == 200
    #     assert response.get_json() == [{
    #         'username': 'testuser1',
    #         'itemEncryptionPublicKey': 'c1',
    #         'deleted': False,
    #         'modified': 12345678902,
    #         'created': 12345678901,
    #     },
    #     {
    #         'username': 'testuser2',
    #         'itemEncryptionPublicKey': 'c2',
    #         'deleted': False,
    #         'modified': 12345678903,
    #         'created': 12345678902,
    #     }]

    def test_create_users_one_user(self):
        response = self.client.post("/users", json=[{
            "usernameAA": "testuser",
            "masterKeyDerivationInformation": "a",
            "masterEncryptionKey": "b",
            "itemEncryptionPublicKey": "c",
            "itemEncryptionSecretKey": "d",
            "settings": "e",
            "deleted": False,
            "modified": 12345678902,
            "created": 12345678901
        }])

        assert response.status_code == 204

        newUser = User.query.get("testuser")
        assert newUser.username == "testuser"
        assert newUser.masterKeyDerivationInformation == "a"
        assert newUser.masterEncryptionKey == "b"
        assert newUser.itemEncryptionPublicKey == "c"
        assert newUser.itemEncryptionSecretKey == "d"
        assert newUser.settings == "e"
        assert newUser.deleted == False
        assert newUser.modified == 12345678902
        assert newUser.created == 12345678901

    # def test_create_users_multiple_users(self):
    #     response = self.client.post("/users", json=[
    #         {
    #             "username": "testuser1",
    #             "masterKeyDerivationInformation": "a1",
    #             "masterEncryptionKey": "b1",
    #             "itemEncryptionPublicKey": "c1",
    #             "itemEncryptionSecretKey": "d1",
    #             "settings": "e1",
    #             "deleted": False,
    #             "modified": 12345678902,
    #             "created": 12345678901
    #         },
    #         {
    #             "username": "testuser2",
    #             "masterKeyDerivationInformation": "a2",
    #             "masterEncryptionKey": "b2",
    #             "itemEncryptionPublicKey": "c2",
    #             "itemEncryptionSecretKey": "d2",
    #             "settings": "e2",
    #             "deleted": False,
    #             "modified": 12345678903,
    #             "created": 12345678902
    #         }
    #     ])

    #     assert response.status_code == 204

    #     newUser1 = User.query.get("testuser1")
    #     assert newUser1.username == "testuser1"
    #     assert newUser1.masterKeyDerivationInformation == "a1"
    #     assert newUser1.masterEncryptionKey == "b1"
    #     assert newUser1.itemEncryptionPublicKey == "c1"
    #     assert newUser1.itemEncryptionSecretKey == "d1"
    #     assert newUser1.settings == "e1"
    #     assert newUser1.deleted == False
    #     assert newUser1.modified == 12345678902
    #     assert newUser1.created == 12345678901

    #     newUser2 = User.query.get("testuser2")
    #     assert newUser2.username == "testuser2"
    #     assert newUser2.masterKeyDerivationInformation == "a2"
    #     assert newUser2.masterEncryptionKey == "b2"
    #     assert newUser2.itemEncryptionPublicKey == "c2"
    #     assert newUser2.itemEncryptionSecretKey == "d2"
    #     assert newUser2.settings == "e2"
    #     assert newUser2.deleted == False
    #     assert newUser2.modified == 12345678903
    #     assert newUser2.created == 12345678902

    # def test_create_users_already_existing(self):
    #     user = User(
    #         username = "testuser",
    #         masterKeyDerivationInformation = "a1",
    #         masterEncryptionKey = "b1",
    #         itemEncryptionPublicKey = "c1",
    #         itemEncryptionSecretKey = "d1",
    #         settings = "e1",
    #         deleted = False,
    #         modified = 12345678902,
    #         created = 12345678901
    #     )

    #     db.session.add(user)
    #     db.session.commit()

    #     response = self.client.post("/users", json=[{
    #         "username": "testuser",
    #         "masterKeyDerivationInformation": "a2",
    #         "masterEncryptionKey": "b2",
    #         "itemEncryptionPublicKey": "c2",
    #         "itemEncryptionSecretKey": "d2",
    #         "settings": "e2",
    #         "deleted": False,
    #         "modified": 12345678903,
    #         "created": 12345678902
    #     }])

    #     assert response.status_code == 409

    #     ## Check that the existing user is unchanged
    #     existingUser = User.query.get("testuser")
    #     assert existingUser.username == "testuser"
    #     assert existingUser.masterKeyDerivationInformation == "a1"
    #     assert existingUser.masterEncryptionKey == "b1"
    #     assert existingUser.itemEncryptionPublicKey == "c1"
    #     assert existingUser.itemEncryptionSecretKey == "d1"
    #     assert existingUser.settings == "e1"
    #     assert existingUser.deleted == False
    #     assert existingUser.modified == 12345678902
    #     assert existingUser.created == 12345678901

    # def test_create_users_missing_json_content(self):
    #     response = self.client.post("/users", json=[{
    #         "usernameINVALID": "testuser",
    #         "masterKeyDerivationInformation": "a2",
    #         "masterEncryptionKey": "b2",
    #         "itemEncryptionPublicKey": "c2",
    #         "itemEncryptionSecretKey": "d2",
    #         "settings": "e2",
    #         "deleted": False,
    #         "modified": 12345678903,
    #         "created": 12345678902
    #     }])

    #     assert response.status_code == 409

    #     ## Check that the existing user is unchanged
    #     existingUser = User.query.get("testuser")
    #     assert existingUser.username == "testuser"
