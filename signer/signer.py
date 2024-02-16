from flask import Flask
from flask import request
from flask import json, jsonify, make_response
import yaml
from flask import Response

import time

from Tezio import TezioWallet

AUTHENTICATION_REQUIRED = False


# slot aliases for the various supported curves
CURVE_ED25519 = 0x01
CURVE_SECP256K1 = 0x02
CURVE_NISTP256 = 0x03
CURVE_NISTP256_AUTH = 0x04

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

pkhsForSlots = config['pkhs']
slotsForPkhs = {a: s for s, a in pkhsForSlots.items()}
addresses = list(slotsForPkhs.keys())

magicBytes = config['magic_bytes']
allowedMagicBytes = bytearray([s for s, a in magicBytes.items() if a == 1])

nodeURL = config['node_url']

# the pkh of the authorized key used to sign incoming requests
# auth_key_pkh = config['policy']['authorized_keys'][0]

lastLevel = 0
lastRound = 0

def bytes_to_int(b: bytearray) -> int:
    nBytes = len(b)
    byteSum = 0
    return



app = Flask(__name__)

@app.route('/')

def home():

    response = make_response('Tezio Siger Application')
    response.status_code = 200

    return response

@app.route('/keys/<pkh>', methods=['GET', 'POST'])

def keys(pkh):
    if pkh in addresses:
        
        if request.method == 'GET':
          
            wallet = TezioWallet(slotsForPkhs[pkh])
            pk = wallet.get_pk(3).decode('utf-8')
            response = jsonify({'public_key': pk})
            response.status_code = 200

            return response
        
        elif request.method == 'POST':

            # dataStr = request.data.decode('utf-8')
            dataStr = request.json
            # dataBytes = bytearray.fromhex(dataStr[1:-2]) # remove "" and line end characters
            dataBytes = bytearray.fromhex(dataStr)
            print(dataStr)

            magicByte = dataBytes[0]
            allowedMagicBytes = config['policy']['signing_keys'][pkh]['magic_bytes']
            
            # is this operation allowed by the policy
            if magicByte in allowedMagicBytes:
                # authorized keys not enabled
                # authSig = None
                authSig = request.args.get('authentication')

                print(authSig)
                authSigBytes = bytearray(authSig, 'utf-8')
                print(request)
                # get level and round from data
                if (magicByte == 0x12 or magicByte == 0x13):
                    level = dataBytes[40:43]
                    round = dataBytes[44:47]
                    
                elif (magicByte == 0x11):
                    pass

        
                try:
                    sign_message = None
                    if(authSig and AUTHENTICATION_REQUIRED):
                        signed_message = bytearray.fromhex('040102') + bytearray.fromhex('a79feaea9fb12af20833db1c2467824197c64027') + dataBytes
                        wallet = TezioWallet(4)
                        wallet.build_packet(0x22, 0x04, 0x04, len(signed_message), signed_message + authSigBytes)
                        status = wallet.query_wallet()
                        print(status)
                        status = wallet.response
                        print(status)
                        if (status[0] == 0x01):
                            sign_message = True
                        else:
                            sign_message = False
                    else:
                        sign_message = True

                    print(sign_message)
                    
                    if (sign_message):
    
                        wallet2 = TezioWallet(slotsForPkhs[pkh])

                        # signature = wallet.sign(CURVE, MESSAGE_AND SIG_FORMAT, MESSAGE)
                        signature = wallet2.sign(4, dataBytes)
          
                        if (signature == 0):
                            response = make_response('Internal Server Error')
                            response.status_code = 500
                        else:
                            response = make_response(jsonify({'signature': signature.decode('utf-8')}))
                            response.status_code = 200

                        return response
                    else:
                        response = make_response('Unauthorized')
                        response.status_code = 401
                        return response
            
                except: 

                    response = make_response('Internal Server Error')
                    response.status_code = 500

                    return response
                
            else:
                
                response = make_response('Unauthorized')
                response.status_code = 401

                return response
        else:

            response = make_response('Bad Request')
            response.status_code = 400

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
