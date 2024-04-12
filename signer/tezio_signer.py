from flask import Flask, request, json, jsonify, make_response, Response
import yaml
from tezio import TezioHSM
from base58 import b58decode_check

from pytezos.crypto import key, encoding

import time

# TezioHSM_API Parameters
PK_BASE58_CHECKSUM = 0x03
PK_HASH = 0x04
SIG_BASE58_CHECKSUM_MESSAGE_UNHASHED = 0x04
SIG_RAW_BYTES_MESSAGE_HASHED = 0x01  # hashed messages will not be signed because of signing policy looking for magic byte
SIG_BASE58_CHECKSUM_MESSAGE_HASHED = 0x02
SIG_RAW_BYTES_MESSAGE_UNHASHED = 0x03 

SIGNING_KEY_ALIASES = [1, 2, 3]
SIGNING_KEY_PREFIXES = {'tz1': {'auth_prefix': "040100", 'sig_prefix': "edsig"}, 
                      'tz2': {'auth_prefix': "040101", 'sig_prefix': "spsig"},
                      'tz3': {'auth_prefix': "040102", 'sig_prefix': "p2sig"}}
AUTH_KEY_ALIAS = 0

# Constants
PKH_B58_PREFIX_LENGTH = 3
BAUD = 115200

# Load Configuration
with open('config.yaml', 'r') as file:
    config = yaml.safe_load(file)

security = config['security']
allowed_ips = config['allowed_ips']

wallet = TezioHSM(BAUD)

# retrieve pkh of signing keys from Tezio HSM
signing_keys = dict()
for KEY in SIGNING_KEY_ALIASES:
    public_key_hash = wallet.get_pk(KEY, PK_HASH).decode('utf-8')
    pkh_prefix = public_key_hash[0:3]
    signing_keys[public_key_hash] = SIGNING_KEY_PREFIXES[pkh_prefix]
    signing_keys[public_key_hash]['curve_alias'] = KEY

pkhs = list(signing_keys.keys())

# Decode the base58 checksum encoded tezos addresses for the signing keys.
for pkh in pkhs:
    signing_keys[pkh]['pkh_bytes'] = b58decode_check(pkh)[PKH_B58_PREFIX_LENGTH:].hex() # remove prefix

# retrieve pkh of auth key from Tezio HSM
auth_key = {}
auth_key['pkh'] = wallet.get_pk(AUTH_KEY_ALIAS, PK_HASH).decode('utf-8')
auth_key['curve_alias'] = AUTH_KEY_ALIAS
# retrieve auth key pk
auth_pk = wallet.get_pk(auth_key['curve_alias'], PK_BASE58_CHECKSUM).decode('utf-8')
auth_pk_obj = key.Key.from_encoded_key(auth_pk)

app = Flask(__name__)

@app.route('/')
def home():
    response = make_response('Tezio Siger Application')
    response.status_code = 200
    return response

@app.route('/keys/<pkh>', methods=['GET', 'POST'])
def keys(pkh):
    if security['remote_ip_check']: # check if request is from an allowed remote ip
        if request.remote_addr in allowed_ips:
            pass
        else:
            ERROR_403 = make_response('Requests from this address are forbidden.')
            ERROR_403.status_code = 403
            return ERROR_403

    # Is the request for a signing key stored in the Tezio HSM?
    if pkh in pkhs:
        pass
    else:
        ERROR_404 = make_response('Requested public key was not found.')
        ERROR_404.status_code = 404
        return ERROR_404
        
    # Is the request method GET or POST?
    if request.method == 'GET':
        if (config['verbose']):
            print('GET request received...', '\n')
            print(request.url, '\n')
        # wallet = TezioHSM()
        reply = wallet.get_pk(signing_keys[pkh]['curve_alias'], PK_BASE58_CHECKSUM)
        if len(reply) == 1: # error occured, status code returned
            response = jsonify(hex(reply[0]))
            response.status_code = 500 # server error
            return response
        else:
            pk = reply.decode('utf-8')
            response = jsonify({'public_key': pk})
            response.status_code = 200
            return response
        
    elif request.method == 'POST':
        if (config['verbose']):
            print('POST request received...', '\n')
            print(request.url, '\n')
            print(request.json, '\n')

        # data to sign sent with the request
        dataBytes = bytearray.fromhex(request.json)
        # first byte is the magic_byte specifying the opration type
        magicByte = dataBytes[0]
        # authentication signature might be included
        authSig = request.args.get('authentication')
       
        # Does the requested signing key require authentication?
        if security['auth_check']:
            if authSig == None: # authentication is required but no signature was included with request
                ERROR_401 = make_response('A signed request is required for this key.')
                ERROR_401.status_code = 401
                return ERROR_401
            else:
                # validate the signature
                signed_message = bytearray.fromhex(signing_keys[pkh]['auth_prefix']) + bytearray.fromhex(signing_keys[pkh]['pkh_bytes']) + dataBytes
                
                # try pytezos
                valid = auth_pk_obj.verify(authSig,bytes(signed_message))
                
                # wallet = TezioHSM()
                # reply = wallet.verify(auth_key['curve_alias'], SIG_BASE58_CHECKSUM_MESSAGE_UNHASHED, signed_message, authSig)                
                # if reply[0] == 0x00:
                if not valid:
                    ERROR_401 = make_response("Authentication signature is not valid.")
                    ERROR_401.status_code = 401
                    return ERROR_401
                # elif reply[0] != 0x01:
                #    response = jsonify(hex(reply[0]))
                #    response.status_code = 500 # server error
                #    return response
                else:
                    pass

        else:
            pass

        # If we have made it this far, sign the data
        # wallet = TezioHSM()

        # hashed_message = bytearray.fromhex(key.blake2b_32(bytes(dataBytes)).hexdigest())
        # reply = wallet.sign(signing_keys[pkh]['curve_alias'], SIG_BASE58_CHECKSUM_MESSAGE_HASHED, hashed_message)
        # print(reply)
        start = time.time()
        # reply = wallet.sign(signing_keys[pkh]['curve_alias'], SIG_BASE58_CHECKSUM_MESSAGE_UNHASHED, dataBytes)
        reply = wallet.sign(signing_keys[pkh]['curve_alias'], SIG_RAW_BYTES_MESSAGE_UNHASHED, dataBytes)
        end = time.time()
        print("call to HSM time: ", end-start)

        if (len(reply) == 1):
            response = jsonify(hex(reply[0]))
            response.status_code = 500 # server error
            return response
        else:
            start = time.time()
            signature = encoding.base58_encode(reply, bytes(signing_keys[pkh]['sig_prefix'], 'utf-8'))
            # signature = reply
            end = time.time()
            print("post processing: ", end-start)

            response = make_response(jsonify({'signature': signature.decode('utf-8')}))
            response.status_code = 200
            return response

    else:
        response = make_response('Bad Request')
        response.status_code = 400
        return response
        
@app.route('/authorized_keys', methods=['GET'])
def authorized_keys():
    if auth_key['pkh'] == None:
        response = jsonify({})
    else:
        response = make_response(jsonify({'authorized_keys': [auth_key['pkh']]}))
    
    response.status_code = 200
    return response
                                            
# main driver function
if __name__ == '__main__':

	app.run(host="localhost", port=5000, processes=1)
