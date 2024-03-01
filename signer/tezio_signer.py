from flask import Flask
from flask import request
from flask import json, jsonify, make_response
import yaml
from flask import Response

import time

from tezio import TezioHSM

# slot aliases for the various supported curves
CURVE_ED25519 = 0x01
CURVE_SECP256K1 = 0x02
CURVE_NISTP256 = 0x03
CURVE_NISTP256_AUTH = 0x00

# possible formats for retreived public keys
PK_BYTES = 0x01
PK_BYTES_COMPRESSED = 0x02
PK_BASE58_CHECKSUM = 0x03
PK_HASH = 0x04

# possible formats for signing requests
SIG_DEFAULT = 0x00
SIG_BYTES_MESSAGE_HASHED = 0x01
SIG_BASE58_CHECKSUM_MESSAGE_HASHED = 0x02
SIG_BYTES_MESSAGE_UNHASHED = 0x03
SIG_BASE58_CHECKSUM_MESSAGE_UNHASHED = 0x04

# supported operations
OP_GET_PK = 0x11
OP_SIGN = 0x21
OP_VERIFY = 0x22


with open('config.yaml', 'r') as file:
    config = yaml.safe_load(file)

policy = config['policy']
signing_keys = policy['signing_keys']
auth_key = policy['auth_key']
allowed_ips = config['allowed_ips']

knownPkhs = list(policy['signing_keys'].keys())
# print(knownPkhs)

pkhsForSlots = config['pkhs']
slotsForPkhs = {a: s for s, a in pkhsForSlots.items()}
addresses = list(slotsForPkhs.keys())

magicBytes = config['magic_bytes']
allowedMagicBytes = bytearray([s for s, a in magicBytes.items() if a == 1])

nodeURL = config['node_url']

# the pkh of the authorized key used to sign incoming requests
# auth_key_pkh = config['policy']['authorized_keys'][0]


watermark_level = dict({0x11: 0, 0x12: 0, 0x13: 0})
watermark_round = dict({0x11: 0, 0x12: 0, 0x13: 0})


app = Flask(__name__)

@app.route('/')

def home():

    response = make_response('Tezio Siger Application')
    response.status_code = 200

    return response

@app.route('/keys/<pkh>', methods=['GET', 'POST'])

def keys(pkh):

    if request.remote_addr in allowed_ips:
        pass
    else:
        ERROR_403 = make_response('Requests from this address are forbidden.')
        ERROR_403.status_code = 403
        return ERROR_403

    # Is the request for a signing key stored in the Tezio HSM?
    if pkh in knownPkhs:
        pass
    
    else:
        ERROR_404 = make_response('Not Found')
        ERROR_404.status_code = 404
        return ERROR_404
        
    # Is the request method GET or POST?
    if request.method == 'GET':
            
        wallet = TezioHSM(signing_keys[pkh]['curve_alias'])
        pk = wallet.get_pk(3).decode('utf-8')
        response = jsonify({'public_key': pk})
        response.status_code = 200
        return response
        
    elif request.method == 'POST':

        # data to sign sent with the request
        dataBytes = bytearray.fromhex(request.json)
        # first byte is the magic_byte specifying the opration type
        magicByte = dataBytes[0]
        # authentication signature might be included
        authSig = request.args.get('authentication')

         # Does the requested signing key allow the operation type?
        if magicByte in signing_keys[pkh]['allowed_ops']:
            pass
        else:
            ERROR_405 = make_response('Method Not Allowed')
            ERROR_405.status_code = 405
            return ERROR_405

        # Does the requested signing key require authentication?
        if signing_keys[pkh]['auth_req']:
            if authSig == None: # authentication is required but no signature was included with request
                ERROR_401 = make_response('Unauthorized: A signed request is required.')
                ERROR_401.status_code = 401
                return ERROR_401
            else:
                # validate the signature
                signed_message = bytearray.fromhex('040102') + bytearray.fromhex('a79feaea9fb12af20833db1c2467824197c64027') + dataBytes
                wallet = TezioHSM(auth_key['curve_alias'])
                is_valid = wallet.verify(4, signed_message, authSig)                
                if is_valid[0] != 0x01:
                    ERROR_401 = make_response('Unauthorized: Included signature is not valid.')
                    ERROR_401.status_code = 401
                    return ERROR_401
                else:
                    pass

        # Is this a baking request?
        if magicByte in [0x11, 0x12, 0x13]:
            # check level and round are valid
            # level and round should be included in the data to be signed
            current_level = 0
            current_round = 0
            # global watermark_level
            # global watermark_round

            if magicByte in [0x12, 0x13]:
                current_level = int.from_bytes(dataBytes[40:44], "big")
                current_round = int.from_bytes(dataBytes[44:48], "big")
            else:
                print("data: ", dataBytes.hex())
                current_level = int.from_bytes(dataBytes[5:9], "big")
                nFitnessBytes = int.from_bytes(dataBytes[83:87], "big")
                print("n fitness bytes: ", nFitnessBytes)
                current_round = int.from_bytes(dataBytes[87 + nFitnessBytes - 4: 87 + nFitnessBytes], "big")
                print('Baking a Block')
                print("level: ", current_level)
                print("round: ", current_round)

            # if current level and round are the same as the those for last baking operation, don't sign
            if (current_level < watermark_level[magicByte]) or (current_level == watermark_level[magicByte] and current_round <= watermark_round[magicByte]):
                ERROR_403 = make_response('Forbidden')
                ERROR_403.status_code = 403
                return ERROR_403
            else:
                watermark_level[magicByte] = current_level
                watermark_round[magicByte] = current_round
                print(watermark_level)
                print(watermark_round)
                pass 
        else:
            pass

        # If we have made it this far, sign the data
        wallet = TezioHSM(signing_keys[pkh]['curve_alias'])
        signature = wallet.sign(4, dataBytes)
        if (signature == 0):
            ERROR_500 = make_response('Internal Server Error')
            ERROR_500.status_code = 500
            return ERROR_500
        else:
            response = make_response(jsonify({'signature': signature.decode('utf-8')}))
            response.status_code = 200

            return response

    else:

        response = make_response('Bad Request')
        response.status_code = 400

        return response
        
            
    
@app.route('/authorized_keys', methods=['GET'])

def authorized_keys():

    # no authorized keys for signing incoming queries
    # response = jsonify({})
    # response = make_response(jsonify({'authorized_keys': ['tz3bhz3h8CXPeUF4gmsGrsyT7sJUcqhrWpVs']}))
    response = make_response(jsonify(config['policy']['signed_requests']))
    response.status_code = 200
    
    return response
                                            
# main driver function
if __name__ == '__main__':

	app.run(host="localhost", port=5000, processes=1)
