# PassButler API

## Development setup (tested on Ubuntu 16.04)

Install packages:

    $ sudo apt install python3-virtualenv

Setup virtual env:

    $ virtualenv ./passbutler-server-venv --python=python3
    $ source ./passbutler-server-venv/bin/activate

Install dependencies:

    $ pip install flask-httpauth flask-sqlalchemy flask-marshmallow marshmallow marshmallow-sqlalchemy==0.18.0

Install unit testing dependencies:

    $ pip install pytest flask-testing

Change to path of this repository:

    $ cd /path/to/passbuttler-server/

## Unit testing

Run unit tests (add `-v` for more verbosity):

    $ pytest

## Run server for development

Start server:

    $ FLASK_ENV=development PASSBUTLER_SETTINGS=./passbutlerserver.conf ./passbutlerserver.py
