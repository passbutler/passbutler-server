# PassButler API

## Development setup (tested on Ubuntu 16.04)

Install packages:

    $ sudo apt install python3-virtualenv

Setup virtual env:

    $ virtualenv ./passbutler-server-venv --python=python3
    $ source ./passbutler-server-venv/bin/activate

Install dependencies:

    $ pip install flask==1.1.1 flask-httpauth==3.3.0 flask-sqlalchemy==2.4.1 flask-marshmallow==0.11.0 marshmallow==3.4.0 marshmallow-sqlalchemy==0.18.0

Install unit testing dependencies:

    $ pip install pytest==5.3.5 Werkzeug==0.16.1 flask-testing==0.7.1

Change to path of this repository:

    $ cd /path/to/passbuttler-server/

## Unit testing

Run unit tests (add `-v` for more verbosity):

    $ pytest

## Run server for development

Start server:

    $ FLASK_ENV=development PASSBUTLER_SETTINGS=./passbutlerserver.conf ./passbutlerserver.py
