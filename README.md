# Pass Butler server

The Pass Butler server provides the possibility to synchronize passwords between multiple devices.

## Production setup on Debian 10

### Installation

#### Install package from repository (recommended)

Add APT repository:

    $ echo "deb http://apt.pm-codeworks.de buster main" | sudo tee /etc/apt/sources.list.d/pm-codeworks.list

Add APT repository signing key and update package index:

    $ wget -O - http://apt.pm-codeworks.de/pm-codeworks.de.gpg | sudo apt-key add -
    $ sudo apt update

Install the package:

    $ sudo apt install passbutler-server

#### Build and install package manually

Install packages:

    $ sudo apt install devscripts

Build the package:

    $ debuild

Install the package:

    $ sudo dpkg -i ../*.deb

### Deployment with Gunicorn and Nginx

Install the package:

    $ sudo apt install gunicorn3

Add dedicated user and group:

    $ sudo adduser --system --group --disabled-password --home /var/lib/passbutler-server/example/ "passbutler-server-example"

Create socket file and correct owner and permissions:

    $ sudo touch /run/passbutler-server-example.sock
    $ sudo chown passbutler-server-example:passbutler-server-example /run/passbutler-server-example.sock
    $ sudo chmod 0640 /run/passbutler-server-example.sock

Create log file and correct owner:

    $ sudo touch /var/log/passbutler-server-example.log
    $ sudo chown passbutler-server-example:passbutler-server-example /var/log/passbutler-server-example.log

Create configuration file `/etc/passbutler-server/example.conf`:

    DATABASE_FILE = '/var/lib/passbutler-server/example/database.sqlite'
    LOG_FILE = '/var/log/passbutler-server-example.log'

    SECRET_KEY = 'SECRET-KEY-PLACEHOLDER'

    ENABLE_REQUEST_LOGGING = False

    REGISTRATION_ENABLED = True
    REGISTRATION_INVITATION_CODE = 'REGISTRATION-INVITATION-CODE-PLACEHOLDER'

Apply random secret and invitation code:

    $ sudo sed -i "s/SECRET-KEY-PLACEHOLDER/$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1)/g" /etc/passbutler-server/example.conf
    $ sudo sed -i "s/REGISTRATION-INVITATION-CODE-PLACEHOLDER/$(cat /dev/urandom | tr -dc 'A-Z0-9' | fold -w 4 | head -n 4 | paste -sd '-')/g" /etc/passbutler-server/example.conf

Create Systemd service file `/etc/systemd/system/passbutler-server-example.service`:

    [Unit]
    Description=Pass Butler synchronization server (example)
    After=network.target
    
    [Service]
    User=passbutler-server-example
    Group=passbutler-server-example
    WorkingDirectory=/var/lib/passbutler-server/example/
    Environment="PASSBUTLER_SETTINGS=/etc/passbutler-server/example.conf"
    ExecStart=/usr/bin/gunicorn3 --name=gunicorn-passbutler-server-example --workers=1 --pythonpath=/opt/venvs/passbutler-server/lib/python3.8/site-packages --bind=unix:/run/passbutler-server-example.sock 'passbutlerserver:createApp()'
    
    [Install]
    WantedBy=multi-user.target

Enable Systemd service:

    $ sudo systemctl start passbutler-server-example.service
    $ sudo systemctl enable passbutler-server-example.service

Add to your Nginx `sites-available/example.vhost` configuration:

    server {
        ...

        location / {
            proxy_pass http://unix:/run/passbutler-server-example.sock;

            include "proxy_params";
        }
    }

Restart Nginx:

    $ sudo systemctl restart nginx.service

## Development setup on Debian 10 / Ubuntu 20

Install package:

    $ sudo apt install python3-virtualenv

Setup virtual environment:

    $ virtualenv ~/Desktop/passbutler-server-venv --python=python3
    $ source ~/Desktop/passbutler-server-venv/bin/activate

Install dependencies:

    $ pip install -r requirements.txt

Install dependencies for testing (optional):

    $ pip install -r dev-requirements.txt

### Unit testing

Run unit tests (add `-v` for more verbosity):

    $ pytest

### Development server

Start server:

    $ FLASK_ENV=development FLASK_APP=passbutlerserver:createApp PASSBUTLER_SETTINGS=./passbutlerserver-example.conf flask run --host 0.0.0.0 --port 5000
