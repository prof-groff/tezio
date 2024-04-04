import serial
import serial.tools.list_ports
from time import sleep
import requests
import binascii

class TezioHSM:
    
    def __init__(self, curve = None):
        self.__prefix: bytes = 0x03 # wallet listens for this byte to begin parsing commands
        self.__baud: int = 57600 # serial coms baud rate
        self.__curve: int = curve # which curve to use 0 - NIST P256 AUTH, 1 - Ed25519, 2 - Secp256k1, 3 - NIST P256
        self.com: str = None
        self.packet: bytearray = None
        self.response: bytearray = None
        
    def __repr__(self):
        print('Instance of TezioHSM\n')
        return 'TezioHSM'
    
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
            if (ser.in_waiting > 0):
                response += ser.read()
                length += 1
            else:
                retries+=1
                sleep(0.001) 
        

        if (length == 0):
            # no bytes arrived
            return 0
        else:
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
        #  sleep(0.02) # short wait
        reply = self.__get_reply(ser)
        if reply == 0:
            return 0
        else:
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
    
    def verify(self, mode, message, signature):
        opCode = 0x22
        param1 = self.__curve
        param2 = mode
        param3 = len(message)
        
        if (mode > 4):
            print('Invalid mode...')
            return 0 # invalid mode
        
        elif (mode > 0 and mode <= 2): 
            # message is already hashed and should be a bytearray of length 32
            if (type(message) != bytearray or len(message) != 32):
                print('Expected hashed message as bytearray...')
                return 0
            data = message
        else:
            # message is not hashed and could be a str of any length
            if (type(message) == str):
                data = bytearray(message, 'utf-8')
            elif (type(message) == bytearray):
                data = message
            else:
                print('Message type not supported...')
                return 0
        
        # add signature
        if (mode%2 == 0): # even means signature is base58 checksum encoded and could be str of any length
            if (type(signature) == str):
                data = data + bytearray(signature, 'utf-8')
            elif (type(signature) == bytearray):
                data = data + signature
            else:
                print('Signature type not supported...')
                return 0
        if (mode%2 == 1): # odd means the signature is raw bytes of length 64
            if (type(signature) != bytearray or len(signature) != 64):
                print('Expected signature to be a bytearray...')
                return 0
            else:
                data = data + signature


        self.build_packet(opCode, param1, param2, param3, data)
        self.query_wallet()
        
        return self.response