from flask import Flask, request, json, jsonify, make_response, Response
import yaml
from tezio import TezioHSM

PK_BASE58_CHECKSUM = 0x03
SIG_BASE58_CHECKSUM_MESSAGE_UNHASHED = 0x04
P2_PKH_PREFIX_LENGTH = 3

with open('config.yaml', 'r') as file:
    config = yaml.safe_load(file)

policy = config['policy']
security = config['security']
signing_keys = policy['signing_keys']
auth_key = policy['auth_key']
auth_key_pkh = auth_key['pkh']
allowed_ips = config['allowed_ips']
hwms = config['high_water_marks']
pkhs = list(policy['signing_keys'].keys())

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
            print('GET request received...')
            print(request.url)
        wallet = TezioHSM(signing_keys[pkh]['curve_alias'])
        reply = wallet.get_pk(PK_BASE58_CHECKSUM)
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
            print('POST request received...')
            print(request.url)
            print(request.json)
        # data to sign sent with the request
        dataBytes = bytearray.fromhex(request.json)
        # first byte is the magic_byte specifying the opration type
        magicByte = dataBytes[0]
        # authentication signature might be included
        authSig = request.args.get('authentication')
         # Does the requested signing key allow the operation type?
        if security['signing_policy_check']:
            if magicByte in signing_keys[pkh]['allowed_ops']:
                pass
            else:
                ERROR_405 = make_response('The request tezos operation is not enabled for this key.')
                ERROR_405.status_code = 405
                return ERROR_405

        # Does the requested signing key require authentication?
        if security['auth_check'] and signing_keys[pkh]['auth_req']:
            if authSig == None: # authentication is required but no signature was included with request
                ERROR_401 = make_response('A signed request is required for this key.')
                ERROR_401.status_code = 401
                return ERROR_401
            else:
                # validate the signature
                if (config['verbose']): 
                    print('authentication signature:', authSig)
                signed_message = bytearray.fromhex('040102') + bytearray.fromhex('a79feaea9fb12af20833db1c2467824197c64027') + dataBytes
                wallet = TezioHSM(auth_key['curve_alias'])
                reply = wallet.verify(SIG_BASE58_CHECKSUM_MESSAGE_UNHASHED, signed_message, authSig)                
                if reply[0] == 0x00:
                    ERROR_401 = make_response("Authentication signature is not valid.")
                    ERROR_401.status_code = 401
                    return ERROR_401
                elif reply[0] != 0x01:
                    response = jsonify(hex(reply[0]))
                    response.status_code = 500 # server error
                    return response
                else:
                    pass

        # Is this a baking request?
        if security['high_water_mark_check'] and magicByte in [0x11, 0x12, 0x13]:
            # check level and round are valid
            # level and round should be included in the data to be signed
            current_level = 0
            current_round = 0
            if magicByte in [0x12, 0x13]:
                current_level = int.from_bytes(dataBytes[40:44], "big")
                current_round = int.from_bytes(dataBytes[44:48], "big")
            else:
                current_level = int.from_bytes(dataBytes[5:9], "big")
                nFitnessBytes = int.from_bytes(dataBytes[83:87], "big")
                current_round = int.from_bytes(dataBytes[87 + nFitnessBytes - 4: 87 + nFitnessBytes], "big")

            # if current level and round are the same as the those for last baking operation, don't sign
            if (current_level < hwms['level'][magicByte]) or (current_level == hwms['level'][magicByte] and current_round <= hwms['round'][magicByte]):
                ERROR_403 = make_response('The request is to sign a baking operation but one of this type has already been signed at this level and round.')
                ERROR_403.status_code = 403
                # print("Level Round Error")
                return ERROR_403
            else:
                hwms['level'][magicByte] = current_level
                hwms['round'][magicByte] = current_round
                if config['verbose']:
                    print('hwms: ', hwms)
                pass 
        
        else:
            pass

        # If we have made it this far, sign the data
        wallet = TezioHSM(signing_keys[pkh]['curve_alias'])
        if config['verbose']:
            print('data: ', dataBytes.hex())
        reply = wallet.sign(SIG_BASE58_CHECKSUM_MESSAGE_UNHASHED, dataBytes)
        if (len(reply) == 1):
            response = jsonify(hex(reply[0]))
            response.status_code = 500 # server error
            return response
        else:
            signature = reply
            print(signature)
            response = make_response(jsonify({'signature': signature.decode('utf-8')}))
            response.status_code = 200
            return response

    else:
        response = make_response('Bad Request')
        response.status_code = 400
        return response
        
@app.route('/authorized_keys', methods=['GET'])
def authorized_keys():
    if auth_key_pkh == None:
        response = jsonify({})
    else:
        response = make_response(jsonify({'authorized_keys': [auth_key_pkh]}))
    
    response.status_code = 200
    return response
                                            
# main driver function
if __name__ == '__main__':

	app.run(host="localhost", port=5000, processes=1)
