#!/usr/bin/env python3

from flask import Flask, request, jsonify, abort, make_response
from flask_marshmallow import Marshmallow
from flask_sqlalchemy import SQLAlchemy
import json
import os

db = SQLAlchemy()
ma = Marshmallow()

class User(db.Model):
    username = db.Column(db.String(64), primary_key=True, nullable=False)
    masterKeyDerivationInformation = db.Column(db.String, nullable=False)
    masterEncryptionKey = db.Column(db.String, nullable=False)
    itemEncryptionPublicKey = db.Column(db.String, nullable=False)
    itemEncryptionSecretKey = db.Column(db.String, nullable=False)
    settings = db.Column(db.String, nullable=False)
    deleted = db.Column(db.Boolean, nullable=False)
    modified = db.Column(db.Integer, nullable=False)
    created = db.Column(db.Integer, nullable=False)

    def __init__(self, username, masterKeyDerivationInformation, masterEncryptionKey, itemEncryptionPublicKey, itemEncryptionSecretKey, settings, deleted, modified, created):
        self.username = username
        self.masterKeyDerivationInformation = masterKeyDerivationInformation
        self.masterEncryptionKey = masterEncryptionKey
        self.itemEncryptionPublicKey = itemEncryptionPublicKey
        self.itemEncryptionSecretKey = itemEncryptionSecretKey
        self.settings = settings
        self.deleted = deleted
        self.modified = modified
        self.created = created

class UserSchema(ma.Schema):
    class Meta:
        fields = ('username', 'itemEncryptionPublicKey', 'deleted', 'modified', 'created')

privateUserSchema = UserSchema()
publicUsersSchema = UserSchema(many=True)





class TestUserSchema(ma.ModelSchema):
    class Meta:
        model = User






## TODO: Really needed?
class UserAlreadyExistsException(Exception):
    pass















def create_app(test_config=None):
    app = Flask(__name__)

    ## General config (production and test related)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    if (test_config is None):
        baseDirectory = os.path.abspath(os.path.dirname(__file__))
        databaseFilePath = os.path.join(baseDirectory, 'passbutler.sqlite')
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + databaseFilePath
    else:
        ## Use `flask_testing.TestCase` fields for configuration
        app.config.from_object(test_config)

    db.init_app(app)
    ma.init_app(app)

    @app.errorhandler(404)
    def not_found(error):
        return make_response(jsonify({'error': 'Not found'}), 404)

    @app.errorhandler(409)
    def already_exists(error):
        return make_response(jsonify({'error': 'Already exists'}), 409)

    @app.errorhandler(400)
    def invalid_request(error):
        return make_response(jsonify({'error': 'Invalid request'}), 400)

    @app.errorhandler(Exception)
    def unhandled_exception(e):
        app.logger.error('Unexpected exception occured: %s', (e))
        return make_response(jsonify({'error': 'Server error'}), 500)

    @app.route("/users", methods=["GET"])
    def get_users():
        allUsers = User.query.all()
        result = publicUsersSchema.dump(allUsers)
        return jsonify(result.data)

    @app.route("/users", methods=["POST"])
    def create_users():
        # unmarshalResult = TestUserSchema(many=True).load(request.json, session=db.session) ## TODO: session?

        # if (len(unmarshalResult.errors) > 0):
        #     app.logger.error('Model validation failed with errors: ' + str(unmarshalResult.errors))
        #     abort(400)



        validationResult = TestUserSchema().validate(data=request.json, many=True) 

        print(validationResult)

        if (len(validationResult) > 0):
            app.logger.error('Model validation failed with errors: ' + str(validationResult))
            abort(400)


        try:
            users = request.json

            for user in users:
                if User.query.filter_by(username=user['username']).first() is None:

                    ## TODO: directly create user from json?
                    db.session.add(User(
                        username = user['username'],
                        masterKeyDerivationInformation = user['masterKeyDerivationInformation'],
                        masterEncryptionKey = user['masterEncryptionKey'],
                        itemEncryptionPublicKey = user['itemEncryptionPublicKey'],
                        itemEncryptionSecretKey = user['itemEncryptionSecretKey'],
                        settings = user['settings'],
                        deleted = user['deleted'],
                        modified = user['modified'],
                        created = user['created']
                    ))
                else:
                    raise UserAlreadyExistsException()

            db.session.commit()
        except UserAlreadyExistsException:
            app.logger.error('The user already exists!')
            abort(409)

        return ('', 204)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', debug=True)
