from flask import Flask
from flask import request
from flask import json, jsonify, make_response
import yaml
from flask import Response

import time

from Tezio import TezioWallet

with open('config.yaml', 'r') as file:
    config = yaml.safe_load(file)

pkhsForSlots = config['pkhs']
slotsForPkhs = {a: s for s, a in pkhsForSlots.items()}
addresses = list(slotsForPkhs.keys())

magicBytes = config['magic_bytes']
allowedMagicBytes = bytearray([s for s, a in magicBytes.items() if a == 1])

nodeURL = config['node_url']

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
            
            if magicByte in allowedMagicBytes:
                # authorized keys not enabled
                # authSig = None
                # authSig = request.args.get('authentication')
                # authSigBytes = bytearray(authSig, 'utf-8')
                # print(authSig)

                # get level and round from data
                if (magicByte == 0x12 or magicByte == 0x13):
                    level = dataBytes[40:43]
                    round = dataBytes[44:47]
                elif (magicByte == 0x11):
                    pass

        
                try:
    
                    wallet = TezioWallet(slotsForPkhs[pkh])
                    signature = wallet.sign(4, dataBytes)
          
                    if (signature == 0):
                        response = make_response('Internal Server Error')
                        response.status_code = 500
                    else:
                        response = make_response(jsonify({'signature': signature.decode('utf-8')}))
                        response.status_code = 200

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
    response = jsonify({})
    # response = make_response(jsonify({'authorized_keys': ['tz3bcN2yEiHacx1YE6xoVu1CfU26J3rRKB1j']}))
    response.status_code = 200
    
    return response
                                            
# main driver function
if __name__ == '__main__':

	app.run(host="localhost", port=5000, processes=1)
