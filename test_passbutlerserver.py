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

    def test_get_users(self):
        username = "testuser"
        masterKeyDerivationInformation = "abc"
        masterEncryptionKey = "b"
        itemEncryptionPublicKey = "c"
        itemEncryptionSecretKey = "d"
        settings = "e"
        deleted = False
        modified = 12345678902
        created = 12345678901

        user = User(
            username = username,
            masterKeyDerivationInformation = masterKeyDerivationInformation,
            masterEncryptionKey = masterEncryptionKey,
            itemEncryptionPublicKey = itemEncryptionPublicKey,
            itemEncryptionSecretKey = itemEncryptionSecretKey,
            settings = settings,
            deleted = deleted,
            modified = modified,
            created = created
        )

        db.session.add(user)
        db.session.commit()

        response = self.client.get("/users")

        assert response.status_code == 200

        ## TODO: json order
        assert b'[{"username":"testuser","created":12345678901,"deleted":false,"itemEncryptionPublicKey":"c","modified":12345678902}]' in response.data



# @pytest.fixture
# def client():
#     testDatabaseFileHandle, testDatabaseFileName = tempfile.mkstemp()

#     passbutlerserver.app.config['DATABASE'] = testDatabaseFileName
#     passbutlerserver.app.config['TESTING'] = True
#     client = passbutlerserver.app.test_client()

#     with passbutlerserver.app.app_context():
#         passbutlerserver.initializeDatabase()

#     yield client

#     os.close(testDatabaseFileHandle)
#     os.unlink(passbutlerserver.app.config['DATABASE'])

# def test_empty_users(client):
#     request = client.get('/users')
#     assert b'[]' in request.data

# def test_create_user(client):

#     username = "testuser",
#     masterKeyDerivationInformation = "a",
#     masterEncryptionKey = "b",
#     itemEncryptionPublicKey = "c",
#     itemEncryptionSecretKey = "d",
#     settings = "e",
#     deleted = False,
#     modified = 12345678902,
#     created = 12345678901,

#     client.post('/users', data=dict(
#         username = username,
#         masterKeyDerivationInformation = masterKeyDerivationInformation,
#         masterEncryptionKey = masterEncryptionKey,
#         itemEncryptionPublicKey = itemEncryptionPublicKey,
#         itemEncryptionSecretKey = itemEncryptionSecretKey,
#         settings = settings,
#         deleted = deleted,
#         modified = modified,
#         created = created
#     ))

#     request = client.get('/users')
#     assert b'[]' in request.data

# # assert client.get('/create').status_code == 200
# # client.post('/create', data={'title': 'created', 'body': ''})
