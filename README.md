# PassButler API

## Development setup (tested on Ubuntu 16.04)

Install packages:

    $ sudo apt install python3-virtualenv

Setup virtual env:

    $ virtualenv ~/passbutler-server-venv --python=python3
    $ source ~/passbutler-server-venv/bin/activate

Install dependencies:

    $ pip install flask-sqlalchemy flask-marshmallow marshmallow-sqlalchemy flask-httpauth

Install unit testing dependencies:

    $ pip install pytest flask-testing

## Unit testing

Run unit tests:

    $ pytest

## Run server

Start server:

    $ PASSBUTLER_SETTINGS=/path/to/passbutlerserver.conf ./passbutlerserver.py
