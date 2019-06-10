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

    def test_get_users_empty(self):

        response = self.client.get("/users")

        assert response.status_code == 200
        assert b'[]' in response.data

    def test_get_users_one_user(self):
        user = User(
            username = "testuser",
            masterKeyDerivationInformation = "a",
            masterEncryptionKey = "b",
            itemEncryptionPublicKey = "c",
            itemEncryptionSecretKey = "d",
            settings = "e",
            deleted = False,
            modified = 12345678902,
            created = 12345678901
        )

        db.session.add(user)
        db.session.commit()

        response = self.client.get("/users")

        assert response.status_code == 200

        ## TODO: json order
        assert b'[{"username":"testuser","created":12345678901,"deleted":false,"itemEncryptionPublicKey":"c","modified":12345678902}]' in response.data
