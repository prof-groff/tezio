/* MIT License

Copyright (c) 2022 Jeffrey R. Groff

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

#include "pbkdf2.h"

void pbkdf2_hmac_sha512(uint8_t *pwd, uint16_t pwd_length, uint8_t *salt, uint16_t salt_length, uint16_t c, uint16_t dk_length, uint8_t *dk)
{
    
    // write zeros to dk
    memset(dk, 0, dk_length);
    // calculate the number of hash outputs to concatinate together (not blocks fed to hash function)
    uint16_t n_hash_outputs = dk_length / SHA512_HASH_SIZE;
    if (dk_length % SHA512_HASH_SIZE)
    {
        n_hash_outputs++;
    }

    // output cursor
    uint16_t _cursor = 0;

    // key input to PRF (here HMAC)
    uint8_t concat_salt[salt_length + 4]; // add four bytes for block index
    memcpy(concat_salt, salt, salt_length);
    memset(&concat_salt[salt_length], 0, 4); // write zeros to 

    uint8_t out[SHA512_HASH_SIZE];

    for (uint16_t i = 0; i < n_hash_outputs; i++)
    {
        uint16_t block_length = min(SHA512_HASH_SIZE, dk_length - _cursor);
        
        memset(out, 0, SHA512_HASH_SIZE); // write zeros to out

        // concatenate counter to salt
        uint16_t counter  = i + 1;
        for (uint8_t j = 0; j < 4; j++)
        {
            concat_salt[salt_length + 4 - j - 1] = (uint8_t)counter & 255; // LSB
            counter >>= 8;
        }

        // do c iterations of PRF
        // first pass
        hmac_sha512(pwd, pwd_length, concat_salt, salt_length + 4, out);
        // XOR block into dk
        for (uint16_t k = 0; k < SHA512_HASH_SIZE; k++)
        {
            dk[_cursor + k] ^= out[k];
        }

        // do for another c-1 passes
        uint8_t new_salt[SHA512_HASH_SIZE];
        uint16_t j = 1;
        while (j < c)
        {
        memcpy(new_salt, out, SHA512_HASH_SIZE);
            // call the pseudo-random function (HMAC)
            hmac_sha512(pwd, pwd_length, new_salt, SHA512_HASH_SIZE, out);

            // XOR block into the output
            for (uint16_t k = 0; k < SHA512_HASH_SIZE; k++)
            {
                dk[_cursor + k] ^= out[k];
            }

            j++;
            
        }

        // advance output cursor
        _cursor += SHA512_HASH_SIZE;
    }
}
