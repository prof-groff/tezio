# Tezio Signer

Tezio Signer is a Python Flask application for relaying Tezos signing requests from Octez to a Tezio HSM. Signing requests are validated against a security and signing policy then forwarded to a Tezio HSM connected via USB using the Tezio HSM API. 

# Introduction

Tezio Signer is located in the <code>signer</code> directory of the repository. The directory contains the app, <code>tezio_signer.py</code>, and a Python class to handle communication with the Tezio HSM, <code>tezio.ph</code>. The security and signing policies for the various keys provisioned on the Tezio HSM are declared in the <code>config.yaml</code> file. 

# Security and Signing Policy

The security policy defined in <code>config.yaml</code>
- enables incoming requests to be validated (remote_ip_check) against a list of allowed IP address (allowed_ips). 
- declares if incoming requests must be signed (auth_check) using a dedicated authentication key (auth_key). The signature requirement can be overriden for individual signing keys (auth_req). 
- specifies if incoming requests are allowed based on the Tezos operation type (signing_policy_check). Allowed operations are ennumerated for each signing key (allowed_ops).
- configures if the level and round of baking operations should be checked (high_water_mark_check) against high water marks (high_water_marks) to prevent accidental double attestation or baking. 

# Running Tezio Signer Using Gunicorn

Flask's built in WSGI server is only meant for testing. Therefore, it is advisable to run Tezio Signer using a production-ready WSGI server like Gunicorn. 

## Install Gunicorn

```console
sudo apt-get update
sudo apt-get install gunicorn
```

## Run the App

```console
cd [PATH_TO_TEZIO_REPO]/signer
chmod u+x tezio_signer.py
gunicorn --bind 127:0.0.1:[PORT] tezio_signer:app
```

# Running Tezio Signer as a Persistent Daemon 

There are several options to accomplish this. One possibility is to run as a background process using Supervisor. 

## Install Supervisor

```console
sudo apt-get update
sudo apt-get install supervisor
```

## Check Supervisor Status

```console
sudo systemctl status supervisor
```

## Create a Configuration File for Tezio Signer

```console
cd /etc/supervisor/conf.d
sudo nano tezio-signer.conf
```

## Compose the Configuration File's Content

```
[program:tezio_signer_flask_app_via_gunicorn]
user=[USER_NAME]
directory=[PATH_TO_TEZIO_REPO]/signer
command=gunicorn --bind 127.0.0.1:[PORT] tezio_signer:app
autostart=true
autorestart=true
stdout_logfile=[PATH_TO_TEZIO_REPO]/signer/tezio_signer_out.log
stderr_logfile=[PATH_TO_TEZIO_REPO]/tezio_signer.log
```

## Update Supervisor

```console
sudo supervisorctl reread
sudo supervisorctl update
```

## Check Daemon Status

```console
sudo supvervisorctl status
```

## Requirements

pip install flask, base58, pyserial