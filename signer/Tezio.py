import serial
import serial.tools.list_ports
from time import sleep
import requests
import binascii

class TezioWallet:
    
    def __init__(self, curve = None):
        self.__prefix: bytes = 0x03 # wallet listens for this byte to begin parsing commands
        self.__baud: int = 57600 # serial coms baud rate
        self.__curve: int = curve # which curve to use 1 - Ed25519, 2 - Secp256k1, 3 - NIST P256
        self.com: str = None
        self.packet: bytearray = None
        self.response: bytearray = None
        
    def __repr__(self):
        print('Instance of TezioWallet\n')
        return 'TezioWallet'
    
    # some useful functions for interacting with the wallet
    def __crc16(self, _data: bytes, reg: int = 0x0000, poly: int = 0x8005) -> int:
        if (_data == None):
            return 0
    
        for octet in _data:
            for i in range(8):
                msb = reg & 0x8000
                if octet & (0x80 >> i):
                    msb ^= 0x8000
                reg <<= 1
                if msb:
                    reg ^= poly
            reg &= 0xFFFF
    
        return reg

    def __find_arduino_port(self) -> str:
        ports = serial.tools.list_ports.comports()
        for each in ports:
            port = str(each)
            if 'Arduino' in port:
                self.com = port.split(' ')[0]
                return 1
        print('No connected Arduino found...')
        return 0

    def __open_serial(self) -> serial.Serial:
        ser = serial.Serial(self.com, self.__baud)
        if (not ser.is_open):
            return None
        return ser

    def __send_packet(self, ser: serial.Serial) -> int:
        if (ser.write(self.packet) == 0):
            return 0
        return 1

    def __get_reply(self, ser: serial.Serial) -> bytearray:
        response = bytearray([])
        retries = 0
        length = 0
        expectedLength = 0

        # wait for the first two bytes to arrive
        while (ser.in_waiting < 2 and retries < 500):
            retries+=1 
            sleep(0.02) # wait up to 10 seconds

        # if the first two bytes arrived read them (length bytes)
        if (ser.in_waiting > 1):
            response += ser.read()
            response += ser.read()
            expectedLength = response[0] + (response[1] << 8)
            length = 2

        # then read in the rest of the response
        retries = 0
        while (length < expectedLength and retries < 200):
            if (ser.in_waiting == 0):
                retries+=1
                sleep(0.001) 
            else:
                response += ser.read()
                length+=1
        
        return response

    def __close_serial(self, ser: serial.Serial) -> int:
        ser.close()
        return 1

    def __validate_reply(self, reply: bytearray) -> int:
    
        checkSum = self.__crc16(reply[:-2]) # last two bytes are checksum
        length = reply[0] + (reply[1] << 8) # first two bytes are length bytes
        if (checkSum & 0xFF == reply[-2] and checkSum >> 8 == reply[-1] and length == len(reply)):
            return 1
        else:
            return 0
    
    def __parse_reply(self, reply: bytearray) -> bytearray:
        if (self.__validate_reply(reply) == 0):
            self.response = None
            return 0
        else:
            self.response = reply[2:-2] # chop off the two length bytes and the two checksum bytes
            return 1
     
  

    # PUBLIC
    
    def build_packet(self, opCode: bytes, param1: bytes = None, param2: bytes = None, param3: int = None, data: bytearray = None) -> bytearray: 
    
        packetLength = 5; # minimum length is two length byte, one opCode byte, and two checksum bytes
        body = [opCode]
    
        if (param1 is not None):
            packetLength+=1
            body+=[param1]
        if (param2 is not None):
            packetLength+=1
            body+=[param2]
        if (param3 is not None):
            packetLength+=2 # int will be represented as two bytes with LSB first
            body+=[param3 & 0xFF, param3 >> 8]
        if (data is not None):
            packetLength+=len(data)
            body+=data
        
        body = [packetLength & 0xFF, packetLength >> 8] + body
    
        checkSum = self.__crc16(body)
    
        self.packet = bytearray([self.__prefix] + body + [checkSum & 0xFF, checkSum >> 8])
    
        return 1

    def query_wallet(self) -> bytearray:  
        if (self.__find_arduino_port() == 0):
            return 0
        if (self.com is None):
            return 0
        ser = self.__open_serial()
        if (ser is None):
            return 0
        if (self.__send_packet(ser) == 0):
            return 0
        sleep(0.02) # short wait
        reply = self.__get_reply(ser)
        self.__parse_reply(reply)
        if (self.response is None):
            return 0
        else:
            return 1
        
    def get_pk(self, mode):
        opCode = 0x11
        
        if (mode < 1 or mode > 4):
            return 0
        
        param1 = self.__curve
        param2 = mode
        self.build_packet(opCode, param1, param2)
        self.query_wallet()
        return self.response
    
    def sign(self, mode, message = None):
        opCode = 0x21
        param1 = self.__curve
        param2 = mode
        param3 = 0x0000 # not used but needed in packet if data is included
        
        if (mode > 4):
            print('Invalid mode...')
            return 0 # invalid mode
        
        if (mode == 0): # return default signature
            # do nothing, no message to sign
            param3 = None # not needed at all since there is no message
            data = None
        elif (mode > 0 and mode <= 2): 
            # message is already hashed and should be a bytearray of length 32
            if (type(message) != bytearray or len(message) != 32):
                print('Expected hashed message as bytearray...')
                return 0
            data = message
        else:
            # message is not hashed and should be a str of any length
            if (type(message) == str):
                data = bytearray(message, 'utf-8')
            elif (type(message) == bytearray):
                data = message
            else:
                print('Message type not supported...')
                return 0
        
        self.build_packet(opCode, param1, param2, param3, data)
        self.query_wallet()
        
        return self.response

class TezioRPC:
    
    def __init__(self, nodeURL: str, myWallet: TezioWallet):
            
            self.wallet = myWallet
            self.nodeURL = nodeURL
            self.account = self.wallet.get_pk(4).decode('utf-8')
            self.__defaultSignature = self.wallet.sign(0).decode('utf-8')
            self.__branch = None
            self.__chain_id = None
            self.__protocol = None
            self.__counter = None
            
            self.__min_fee_mutez = 100
            self.__min_fee_per_byte_mutez = 1 # number of bytes in forged and signed operation
            self.__min_fee_per_gas_mutez = 0.1
            self.__origination_size = 257
            self.__cost_per_byte = 250
            
 
    def __repr__(self):
        print('Instance of TezioRPC\n')
        return 'TezioRPC'
    
    def __get_request(self, URL):
        r = requests.get(URL)
        if r.status_code == 200:
            reply = r.json()
        else: 
            print('RPC failed...')
            reply = None
        return reply
    
    def __post_request(self, URL, data, params = None):
        if (params is None): # data is probably JSON formatted 
            r = requests.post(URL, json = data)
        else:
            r = requests.post(URL, params = params, data = data)
        if r.status_code == 200:
            reply = r.json()
        else:
            print('RPC failed...')
            print(r.json())
            reply = None
        return reply

    def __post_request_json(self, URL, data):
        r = requests.post(URL, json = data)
        if r.status_code == 200:
            reply = r.json()
        else:
            print('RPC failed...')
            print(r.json())
            reply = None
        return reply
    
    def __post_request_params_data(self, URL, params, data):
        r = requests.post(URL, params = params, data = data)
        if r.status_code == 200:
            reply = r.json()
        else:
            print('RPC failed...')
            print(r.json())
            reply = None
        return reply
    
    def __update_chain_data(self):
        header = self.header()
        self.__chain_id = header['chain_id']
        self.__protocol = header['protocol']
        self.__branch = header['hash']
        return
    
    def __increment_counter(self, counter):
        self.__counter = str(int(counter)+1)
        return
    
    def __update_counter_and_chain_data(self): 
        self.__update_chain_data()
        self.__increment_counter(self.counter())
        return
    
    
    
    def __forge_operation(self, operation):
        
        # forge operation
        forgedOperation = '03' + self.remote_forge(operation) # add prefix
        # convert to bytearray for signing
        binaryForgedOperation = bytearray(binascii.unhexlify(forgedOperation))
        
        return binaryForgedOperation
    
    def __simulate_operation(self, operation):
        # sig is base58 encoded string
        # simulate operation with run_operation RPC
        
        # form JSON for run_operation
        json = {}
        json['operation'] = operation.copy() # make a copy so original isn't modified
        json['operation']['signature'] = self.__defaultSignature # format needs to be valid but not validated
        json['chain_id'] = self.__chain_id

        # call run_operation to estimate gas
        print('Simulating operation...')
        result = self.run_operation(json)
        
        if (result is None):
            print('RPC call for simulation failed...')
            return 0
        
        status = result['contents'][0]['metadata']['operation_result']['status']
        
        if (status != 'applied'):
            print('Operation not applied...')
            print(result)
            return 0
        else:
            return result
        
        
        return result
    
    def __preapply_operations(self, operation, signature):
        
        print('Preapply operation...')
        
        json = operation.copy() # make a copy so original isn't modified
        
        # form JSON for preapply operations
        json['protocol'] = self.__protocol
        json['signature'] = signature
       
        result = self.preapply([json]) # can take a list of operations
        
        if (result is None):
            print('RPC call for preapply failed...')
            return 0
        
        status = result[0]['contents'][0]['metadata']['operation_result']['status']
        
        if (status != 'applied'):
            ('Operation not applied...')
            print(result)
            return 0
        else:
            return 1
        
    def __inject_operation(self, binaryForgedOperation):
        # instead of reusing signature from preapply (and decoding it from base58), it's easier to get a new one
        # hash binary forged operation then sign (return raw 64 byte sigtature, mode 3)
        binarySignature = self.wallet.sign(3, binaryForgedOperation)
        

        # prepare operation and signature for injection
        # concatinate (ingore 0x03 prefix) and convert to string
        data = binascii.hexlify(binaryForgedOperation[1:] + binarySignature).decode('utf-8') 
        data = '"' + data + '"' # add double quotes

        print('Injecting operation...')
        result = self.injection_operation(data)
        if (result is None):
            print('RPC call to inject opertion failed...')
            return 0
        
        return result

    
    def __estimate_fee(self, nBytes, consumedGas, buffer = 1):
        fee = str(int((self.__min_fee_mutez + self.__min_fee_per_byte_mutez * nBytes + self.__min_fee_per_gas_mutez * consumedGas)*buffer))
        return fee
    
    def __estimate_storage_limit(self, nBytes, buffer = 1):
        storage_limit = str(int(self.__cost_per_byte*nBytes*buffer))
        return storage_limit
    
    def __estimate_baker_and_burn_fees(self, operation, simResult, buffer = 1):
        # simResult - result of the run_operation simulation
        # operation - json of operation to be injected
        # buffer - an extra factor to make sure fee and storage are enough
        consumedGas = simResult['contents'][0]['metadata']['operation_result']['consumed_gas']
        gas_limit = str(int(int(consumedGas) + 100)) # add 100 as a buffer
        
        # baker fee (in part) is based on the size of operation in binary that will be injected. 
        # storage fee (burn) is related to the amount of bytes written to the blockchain. 
        
        
        # forge operation (to estimate bytes in final injected operation)
        # actual injection will ignore the 0x03 prefix so this estimate may be 1 byte too large (shrug)
        # actual fees and storage will be different too so this may be more than 1 byte too large
        binaryOperation = self.__forge_operation(operation)
        nBytesOperation = len(binaryOperation) + 64 # 64 for signature that will be appended later
       
        
        # estimate fees and storage
        fee_estimate = self.__estimate_fee(nBytesOperation, int(gas_limit), buffer) 
        
        
        kind = operation['contents'][0]['kind']
        if (kind == 'transaction'):
            storage_estimate = '0'
        elif (kind == 'delegation'):
            storage_estimate = '0'
        elif (kind == 'reveal'):
            storage_estimate = self.__estimate_storage_limit(self.__origination_size, buffer)
        else:
            storage_estimate = '0'
        
        
        print('Baker fees and storage (burn) estimates:')
        print('Fee: {} tez'.format(int(fee_estimate)/1000000))
        print('Storage: {} tez'.format(int(storage_estimate)/1000000))
        
        if (input("Inject operation? (Y/N)") != 'Y'):
            return 0
        

        # update gas_limit, storage_limit, and fee in operation contents

        operation['contents'][0]['gas_limit'] = gas_limit
        operation['contents'][0]['fee'] = fee_estimate
        operation['contents'][0]['storage_limit'] = storage_estimate
        
        # update binary forged operation
        binaryOperation = self.__forge_operation(operation)
        
        return binaryOperation
        
    def __simulate_preapply_inject(self, operation):
        # SIMULATE OPERATION (RUN_OPERATION)
        result = self.__simulate_operation(operation)
        if (result == 0):
            return 0
        
        # ESTIMATE BAKER FEE AND STORAGE (BURN), UPDATE OPERATION CONTENTS, AND RETURN FORGED OPERATION
        binaryOperation = self.__estimate_baker_and_burn_fees(operation, result, 1.1)
        
        # hash then sign the operation, signature returned in base58 (mode4)
        # and decoded from bytes into a string
        signature = self.wallet.sign(4,binaryOperation).decode('utf-8')
        
        # DO PREAPPLY
        if (self.__preapply_operations(operation, signature) == 0):
            return 0

        # INJECT OPERATION
        result = self.__inject_operation(binaryOperation)
        if (result == 0):
            return 0
        else:
            print('Operation hash...')
            print(result)
            
        return result
    
    
    
    def counter(self):
        URL = '{nodeURL}/chains/main/blocks/head/context/contracts/{account}/counter'.format(nodeURL = self.nodeURL, account = self.account)
        return self.__get_request(URL)
    
    def balance(self):
        URL = '{nodeURL}/chains/main/blocks/head/context/contracts/{account}/balance'.format(nodeURL = self.nodeURL, account = self.account)
        return self.__get_request(URL)
    
    def constants(self):
        URL = '{nodeURL}/chains/main/blocks/head/context/constants'.format(nodeURL = self.nodeURL)
        return self.__get_request(URL)
    
    def header(self):
        URL = '{nodeURL}/chains/main/blocks/head/header'.format(nodeURL = self.nodeURL)
        return self.__get_request(URL)
    
    def block_hash(self):
        URL = '{nodeURL}/chains/main/blocks/head/hash'.format(nodeURL = self.nodeURL)
        return self.__get_request(URL)
    
    def remote_forge(self, data):
        URL = '{nodeURL}/chains/main/blocks/head/helpers/forge/operations'.format(nodeURL = self.nodeURL)
        return self.__post_request(URL, data)
    
    def run_operation(self, data):
        URL = '{nodeURL}/chains/main/blocks/head/helpers/scripts/run_operation'.format(nodeURL = self.nodeURL)
        return self.__post_request(URL, data)
    
    def preapply(self, data):
        URL = '{nodeURL}/chains/main/blocks/head/helpers/preapply/operations'.format(nodeURL = self.nodeURL)
        return self.__post_request(URL, data)
    
    def injection_operation(self, data):
        params = {'chain': 'main'}
        URL = '{nodeURL}/injection/operation'.format(nodeURL = self.nodeURL)
        return self.__post_request(URL, data, params)
    
    
    def reveal(self):
        
        self.__update_counter_and_chain_data()
        
        # get public key (base58, mode 3)
        publicKey = self.wallet.get_pk(3).decode('utf-8')
        
        # operation structure with default values for fee, gas_limit, and storage_limit
        operation = {'branch': self.__branch, 
                     'contents': [{'kind': 'reveal', 
                                   'source': self.account, 
                                   'fee': '10000', 
                                   'counter': self.__counter, 
                                   'gas_limit': '10000', 
                                   'storage_limit': '10000', 
                                   'public_key': publicKey}]}
        
        result = self.__simulate_preapply_inject(operation)
        
        return result
    
    
    def send_mutez(self, amount, destination):
        
        self.__update_counter_and_chain_data()
        
        # operation structure with default values for fee, gas_limit, and storage_limit
        operation = {'branch': self.__branch, 
                     'contents': [{'kind': 'transaction', 
                                   'source': self.account, 
                                   'fee': '10000', 
                                   'counter': self.__counter, 
                                   'gas_limit': '10000', 
                                   'storage_limit': '10000', 
                                   'amount': str(amount), 
                                   'destination': str(destination)}]}


        result = self.__simulate_preapply_inject(operation)
        
        return result


    def delegation(self, delegate):
        
        self.__update_counter_and_chain_data()
        
        # operation structure with default values for fee, gas_limit, and storage_limit
        operation = {'branch': self.__branch, 
                     'contents': [{'kind': 'delegation',
                                   'source': self.account, 
                                   'fee': '10000', 
                                   'counter': self.__counter, 
                                   'gas_limit': '10000', 
                                   'storage_limit': '10000', 
                                   'delegate': delegate}]}
        
        
        result = self.__simulate_preapply_inject(operation)
        
        return result