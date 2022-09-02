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
        retries = 500
        for each in range(retries):
            if ser.in_waiting > 0:
                break
            else:
                sleep(0.02)
        if (ser.in_waiting == 0):
            return None
        else:
            while (ser.in_waiting > 0):
                response += ser.read()
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
        operation['signature'] = self.__defaultSignature # format needs to be valid but not validated
        json['operation'] = operation
        json['chain_id'] = self.__chain_id

        # call run_operation to estimate gas
        result = self.run_operation(json)
        
        return result
    
    def __preapply_operations(self, operation, signature):
        
        # form JSON for preapply operations
        operation['protocol'] = self.__protocol
        operation['signature'] = signature
       
        result = self.preapply([operation]) # can take a list of operations
        return result
    
    def __estimate_fee(self, nBytes, consumedGas, buffer = 1):
        fee = str(int((self.__min_fee_mutez + self.__min_fee_per_byte_mutez * nBytes + self.__min_fee_per_gas_mutez * consumedGas)*buffer))
        return fee
    
    def __estimate_storage_limit(self, nBytes, buffer = 1):
        storage_limit = str(int(self.__cost_per_byte*nBytes*buffer))
        return storage_limit
    
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
        
        # get public key (base58, mode 3)
        publicKey = self.wallet.get_pk(3).decode('utf-8')
        
        # retreive chain_id, protocol, branch (hash)
        self.__update_chain_data()
        
        # retreive and increment counter
        self.__increment_counter(self.counter())
        
        # form operation 
        contents = [{'kind': 'reveal', 'source': self.account, 'fee': '10000', 'counter': self.__counter, 'gas_limit': '10000', 'storage_limit': '10000', 'public_key': publicKey}]
 
        operation = {'branch': self.__branch, 'contents': contents}
        
        # forge operation
        binaryForgedOperation = self.__forge_operation(operation)
        
        # the fee (in part) is ostensibly based on the size of operation in binary that will be injected. Storage is related to the amount of bytes written to the blockchain. I don't really know how to estimate these values well. Needs work.
        self.__nBytesOperation = len(binaryForgedOperation) + 64 # 64 for signature
        
        # hash then sign the operation, signature returned in base58 (mode4)
        # and decoded from bytes into a string
        # signature = self.wallet.sign(4, binaryForgedOperation).decode('utf-8')
        
        # simulate operation
        print('Simulating operation...')
        result = self.__simulate_operation(operation)

        if (result is None):
            print('RPC call for simulation failed...')
            return 0
        
        print('Results...')
        print(result)
        
        status = result['contents'][0]['metadata']['operation_result']['status']
        
        if (status != 'applied'):
            print('Operation not applied...')
            return 0
        
        
        consumedGas = result['contents'][0]['metadata']['operation_result']['consumed_gas']
        
        fee_estimate = self.__estimate_fee(nBytesOperation, consumedGas, 1.1) # buffer 1.1, add 10% to minimum estimated fee
        storage_estimate = self.__estimate_storage_limit(self.__origination_size, 1.1)

        # update gas_limit, storage_limit, and fee
        gas_limit = str(int(int(consumedGas)*1.1)) # add 10% buffer 
        contents[0]['gas_limit'] = gas_limit
        contents[0]['fee'] = fee_estimate
        contents[0]['storage_limit'] = storage_estimate
        
        # do pre-apply
        operation = {'branch': branch, 'contents': contents}
        
        # forge operation
        binaryForgedOperation = self.__forge_operation(operation)
        # hash then sign the operation, signature returned in base58 (mode4)
        # and decoded from bytes into a string
        signature = self.wallet.sign(4, binaryForgedOperation).decode('utf-8')
        
        print('Preapply operation...')
        result = self.__preapply_operations(operation, signature)
        
        # form JSON for preapply operations
        # json = [{}]
        # json[0]['protocol'] = protocol
        # json[0]['branch'] = branch
        # json[0]['contents'] = contents
        # json[0]['signature'] = signature
        
        
        # result = self.preapply(json)
  
        if (result is None):
            print('RPC call for preapply failed...')
            return 0
        
        print('Results...')
        print(result)
        
        status = result[0]['contents'][0]['metadata']['operation_result']['status']
        
        if (status != 'applied'):
            ('Operation not applied...')
            return 0

        # need a binary version of the signature to inject. could decode last signature from base58 (probably best) or get a new signature from wallet in binary (64 bytes, easier)
        
        # hash then sign (raw 64 bytes) the binary forged operation (mode 3)
        binarySignature = self.wallet.sign(3, binaryForgedOperation)
        

        # prepare operation and signature for injection
        data = binascii.hexlify(binaryForgedOperation[1:] + binarySignature).decode('utf-8') # concatinate (ingore 0x03 prefix) and convert to string
        data = '"' + data + '"' # add double quotes
        # print(data)

        
        print('Injecting operation...')
        result = self.injection_operation(data)
        if (result is None):
            print('RPC call to inject opertion failed...')
            return 0
        
        print('Results...')
        print(result)
        
        return result
    
    
    def send_mutez(self, amount, destination):
        
        # retreive chain_id, protocol, branch (hash)
        self.__update_chain_data()
        
        # retreive and increment counter
        self.__increment_counter(self.counter())
        
        # compose operation with default values for fee, gas_limit, and storage_limit
        contents = [{'kind': 'transaction', 'source': self.account, 'fee': '10000', 'counter': self.__counter, 'gas_limit': '10000', 'storage_limit': '10000', 'amount': str(amount), 'destination': str(destination)}]
 
        operation = {'branch': self.__branch, 'contents': contents}
        
        # forge operation
        binaryForgedOperation = self.__forge_operation(operation)
        
        
        
        # simulate operation
        print('Simulating operation...')
        result = self.__simulate_operation(operation)

        if (result is None):
            print('RPC call for simulation failed...')
            return 0
        
        # print('Results...')
        # print(result)
        
        status = result['contents'][0]['metadata']['operation_result']['status']
        
        if (status != 'applied'):
            print('Simulated operation not applied...')
            return 0
        
        
        consumedGas = result['contents'][0]['metadata']['operation_result']['consumed_gas']
        
        # the fee (in part) is based on the size of operation in binary that will be injected. Storage is related to the amount of bytes written to the blockchain. 
        # I will attemp to estimate these values. 
        nBytesOperation = len(binaryForgedOperation) + 64 # 64 for signature
        
        # estimate fee - buffer = 1.1 to add 10% to minimum estimated fee
        fee_estimate = self.__estimate_fee(nBytesOperation, int(consumedGas), 1.1) 
        storage_estimate = '0'
        
        # print('Consumed Gas, Fee Estimate, Storage Estimate...')
        # print(consumedGas)
        # print(fee_estimate)
        # print(storage_estimate)
        
        print('Fee and storage estimates:')
        print('Fee: {} tez'.format(int(fee_estimate)/1000000))
        print('Storage: {} tez'.format(int(storage_estimate)/1000000))
        
        if (input("Continue? (Y/N)") != 'Y'):
            return 0
        

        # update gas_limit, storage_limit, and fee
        gas_limit = str(int(int(consumedGas)*1.1)) # add 10% buffer 
        contents[0]['gas_limit'] = gas_limit
        contents[0]['fee'] = fee_estimate
        contents[0]['storage_limit'] = storage_estimate
        
        # do pre-apply
        operation = {'branch': self.__branch, 'contents': contents}
        
        # forge operation
        binaryForgedOperation = self.__forge_operation(operation)
        # hash then sign the operation, signature returned in base58 (mode4)
        # and decoded from bytes into a string
        signature = self.wallet.sign(4,binaryForgedOperation).decode('utf-8')
        
        print('Preapply operation...')
        result = self.__preapply_operations(operation, signature)
        print(result)
  
        if (result is None):
            print('RPC call for preapply failed...')
            return 0
        
        print('Results...')
        print(result)
        
        status = result[0]['contents'][0]['metadata']['operation_result']['status']
        
        if (status != 'applied'):
            ('Operation not applied...')
            return 0

        # Need a binary version of the signature to inject. Could decode signature used for preapply (less calculation) but her a new signature is requested from the wallet in binary (64 bytes) because this is easier
        
        # hash then sign (raw 64 bytes) the binary forged operation (mode 3)
        binarySignature = self.wallet.sign(3, binaryForgedOperation)
        

        # prepare operation and signature for injection
        data = binascii.hexlify(binaryForgedOperation[1:] + binarySignature).decode('utf-8') # concatinate (ingore 0x03 prefix) and convert to string
        data = '"' + data + '"' # add double quotes
        # print(data)

        
        print('Injecting operation...')
        result = self.injection_operation(data)
        if (result is None):
            print('RPC call to inject opertion failed...')
            return 0
        
        print('Results...')
        print(result)
        
        return result


    def delegation(self, delegate):
        
        self.__update_chain_data()
        self.__increment_counter(self.counter())
        
        contents = [{'kind': 'delegation','source': self.account, 'fee': '10000', 'counter': self.__counter, 'gas_limit': '10000', 'storage_limit': '10000', 'delegate': delegate}]
        
        
        operation = {'branch': self.__branch, 'contents': contents}
        
        # forge operation
        binaryForgedOperation = self.__forge_operation(operation)
        
        
        nBytesOperation = len(binaryForgedOperation) + 64 # 64 for signature
        
        # hash then sign the operation, signature returned in base58 (mode4)
        # and decoded from bytes into a string
        # signature = self.wallet.sign(4, binaryForgedOperation).decode('utf-8')
        
        # simulate operation
        print('Simulating operation...')
        result = self.__simulate_operation(operation)

        if (result is None):
            print('RPC call for simulation failed...')
            return 0
        
        print('Results...')
        print(result)
        
        status = result['contents'][0]['metadata']['operation_result']['status']
        
        if (status != 'applied'):
            print('Operation not applied...')
            return 0
        
        
        consumedGas = result['contents'][0]['metadata']['operation_result']['consumed_gas']
        
        fee_estimate = self.__estimate_fee(nBytesOperation, int(consumedGas), 1.1) # add 10%, multiplier 1.1
        storage_estimate = '0'
        
        print('Consumed Gas, Fee Estimate, Storage Estimate...')
        print(consumedGas)
        print(fee_estimate)
        print(storage_estimate)

        # update gas_limit, storage_limit, and fee
        gas_limit = str(int(int(consumedGas)*1.1)) # add 10% buffer 
        contents[0]['gas_limit'] = gas_limit
        contents[0]['fee'] = fee_estimate
        contents[0]['storage_limit'] = storage_estimate
        
        # do pre-apply
        operation = {'branch': self.__branch, 'contents': contents}
        
        # forge operation
        binaryForgedOperation = self.__forge_operation(operation)
        # hash then sign the operation, signature returned in base58 (mode4)
        # and decoded from bytes into a string
        signature = self.wallet.sign(4,binaryForgedOperation).decode('utf-8')
        
        print('Preapply operation...')
        result = self.__preapply_operations(operation, signature)
        print(result)
        
        
        if (result is None):
            print('RPC call for preapply failed...')
            return 0
        
        print('Results...')
        print(result)
        
        status = result[0]['contents'][0]['metadata']['operation_result']['status']
        
        if (status != 'applied'):
            ('Operation not applied...')
            return 0

        # Need a binary version of the signature to inject. Could decode signature used for preapply (less calculation) but her a new signature is requested from the wallet in binary (64 bytes) because this is easier
        
        # hash then sign (raw 64 bytes) the binary forged operation (mode 3)
        binarySignature = self.wallet.sign(3, binaryForgedOperation)
        

        # prepare operation and signature for injection
        data = binascii.hexlify(binaryForgedOperation[1:] + binarySignature).decode('utf-8') # concatinate (ingore 0x03 prefix) and convert to string
        data = '"' + data + '"' # add double quotes
        # print(data)

        
        print('Injecting operation...')
        result = self.injection_operation(data)
        if (result is None):
            print('RPC call to inject opertion failed...')
            return 0
        
        print('Results...')
        print(result)
        
        
        
        return result