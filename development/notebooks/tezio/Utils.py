class Utils():

    def __init__(self):
        
        return
    
    
    def base58(data, prefix = b''): # expected data to be bytearray or bytes
        data = prefix + data
        base58map = ['1', '2', '3', '4', '5', '6', '7', '8',
                    '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
                    'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q',
                    'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                    'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
                    'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
                    'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
                    'y', 'z' ]
    
        b58_size = int(len(data)*138/100) + 1 # minimum size of b58 encode
        digits = [0]*b58_size
        digitslen = 1

        encode_flag = False
        leading_zeros = 0

        for i in range(len(data)):
            if (not(encode_flag) and data[i] == 0):
                leading_zeros = leading_zeros + 1
            if (not(encode_flag) and data[i] != 0):
                encode_flag = True
   
            if (encode_flag):
                carry = data[i] # carry needs to be uint32_t in C++
                for j in range(digitslen):
                    carry = carry + (digits[j]<<8) # digits[j] must be recast as a uint32_t in C++, same as <<8
                    digits[j] = carry%58
                    carry = int(carry/58)
                while (carry > 0):
                    digits[digitslen] = carry%58
                    digitslen = digitslen+1
                    carry=int(carry/58)

        # trim unused digits from digits
        digits = digits[:digitslen]
            
        for k in range(leading_zeros):
            digits.append(0)

        digits.reverse()

        base58_data = ''
        for each in digits:
            base58_data += base58map[each]
        
        return base58_data

