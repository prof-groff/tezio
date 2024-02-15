from flask import Flask
from flask import request
from flask import json, jsonify, make_response
import yaml
from flask import Response

import time
from threading import Lock

from Tezio import TezioWallet

with open('config.yaml', 'r') as file:
    config = yaml.safe_load(file)

accountsForSlots = config['addresses']
# print(accountsForSlots)
slotsForAccounts = {a: s for s, a in accountsForSlots.items()}
# print(slotsForAccounts)
slots = list(accountsForSlots.keys())
accounts = list(slotsForAccounts.keys())


# Flask constructor takes the name of 
# current module (__name__) as argument.
app = Flask(__name__)

lock = Lock()


# The route() function of the Flask class is a decorator, 
# which tells the application which URL should call 
# the associated function.
@app.route('/')
# ‘/’ URL is bound with hello_world() function.
def hello_world():
	return 'Hello World'

@app.route('/keys/<pkh>', methods=['GET', 'POST'])

def keys(pkh):
    if pkh in accounts:
        # print(slotsForAccounts[pkh])
        
        if request.method == 'GET':
            with lock:
                wallet = TezioWallet(slotsForAccounts[pkh])
                pk = wallet.get_pk(3).decode('utf-8')
                pass
            
            response = jsonify({'public_key': pk})
            # print(response)
            return response
        elif request.method == 'POST':
            # time.sleep(0.01) # short wait to slow down requests
            dataStr = request.data.decode('utf-8')
            print(dataStr)
            # print(dataStr[1:-2])
            dataBytes = bytearray.fromhex(dataStr[1:-2]) # remove " from beginning and end and extra character too
            # print(dataBytes)
            
            auth_sig = None
            auth_sig = request.args.get('authentication')
            print(auth_sig)
            
            if (auth_sig):
                print("authentication received")
                
                authBytes = bytearray(auth_sig, 'utf-8')
                # print(authBytes)
            #    print(len(authBytes))
                
                # opCode = 0x22
                # param1 = 0x04
                # param2 = 0x04
                # param3 = len(dataBytes)
                # data = dataBytes + authBytes
                # print(data)
                # print(len(data))
                
                

                # print(param3)
                # print(data)
                
                # validate signature
                
                # wallet = TezioWallet(4) # using validation key
                # pk = wallet.get_pk(4);
                # print(pk)
                # wallet.build_packet(opCode, param1, param2, param3, data);
                # print('Packet to be sent...')
                # print(wallet.packet.hex())
                # print()

                # if (not wallet.query_wallet()):
                #     print('Wallet query failed')

                # else:
                #   print('Signature valid (0x01) or invalid (0x00)...')
                #    print(wallet.response.hex())
            try:
                with lock:
                    wallet = TezioWallet(slotsForAccounts[pkh])
                    signature = wallet.sign(4, dataBytes)
                    pass
                # print(signature)
                # print(signature.decode('utf-8'))
                if (signature == 0):
                    response = make_response('Error')
                    response.status_code = 400
                else:
                    response = make_response(jsonify({'signature': signature.decode('utf-8')}))
                    response.status_code = 200
                return response
            # print(response)
            except: 
                response = make_response('Error')
                response.status_code = 400
                return response
        else:
            response = make_response('Error')
            response.status_code = 400
            return response
    else:
        response = make_response('Error')
        response.status_code = 400
        return response
            
    
@app.route('/authorized_keys', methods=['GET'])

def authorized_keys():
    # authorized keys not implemented yet
    # response = jsonify({'authorized_keys': ['edpkuBsdoxrpMAwPNZSqpgEaFdNz55uqNBrU43pjsBLTE1aM6XecgG']})
    response = jsonify({})
    # response = make_response(jsonify({'authorized_keys': ['tz2UsL2kos6EzKQHynKEdRG5M6JrfDqpXqi5']}))
    response.status_code = 200
    
    return response
                                            
# main driver function
if __name__ == '__main__':

	# run() method of Flask class runs the application 
	# on the local development server.
	app.run(host="localhost", port=5000, processes=1)
