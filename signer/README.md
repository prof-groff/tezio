# Tezio Signer

A Python Flask application to handle Tezos signing requests from Octez. Signing requests are validated against a security and signing policy then forwarded to a Tezio HSM connected via USB using the Tezio HSM API. 

# Security and Signing Policy

The security policy defined in config.yaml
- enables incoming requests to be validated (remote_ip_check) against a list of allowed IP address (allowed_ips). 
- declares if incoming requests must be signed (auth_check) using a dedicated authentication key (auth_key). The signature requirement can be overriden for individual signing keys (auth_req). 
- specifies if incoming requests are allowed based on the Tezos operation type (signing_policy_check). Allowed operations are ennumerated for each signing key (allowed_ops).
- configures if the level and round of baking operations should be checked (high_water_mark_check) against high water marks (high_water_marks) to prevent accidental double attestation or baking. 

# Running Tezio Signer Using Gunicorn

Running the app using Gunicorn is using the built in Flask server. 

## Install Gunicorn

sudo apt-get update
sudo apt-get install gunicorn

## Run the App

cd [PATH_TO_TEZIO_REPO]/signer
chmod u+x tezio_signer.py
gunicorn --bind 127:0.0.1:[PORT] tezio_signer:app

# Running Tezio Signer as a Persistent Daemon 

There are several options to accomplish this. One possibility is to run as a background process using Supervisor. 

## Install Supervisor

sudo apt-get update
sudo apt-get install supervisor

## Check Supervisor Status

sudo systemctl status supervisor

## Create a Configuration File for Tezio Signer

cd /etc/supervisor/conf.d
sudo nano tezio-signer.conf

## Compose the Configuration File's Content

[program:tezio_signer_flask_app_via_gunicorn]
user=[USER_NAME]
directory=[PATH_TO_TEZIO_REPO]/signer
command=gunicorn --bind 127.0.0.1:[PORT] tezio_signer:app
autostart=true
autorestart=true
stdout_logfile=[PATH_TO_TEZIO_REPO]/signer/tezio_signer_out.log
stderr_logfile=[PATH_TO_TEZIO_REPO]/tezio_signer.log

## Update Supervisor

sudo supervisorctl reread
sudo supervisorctl update

## Check Daemon Status

sudo supvervisorctl status