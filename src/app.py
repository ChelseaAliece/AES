import os, codecs, binascii, base64, Crypto
from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode
import time



def keyGen():

    # Generates random base 16 key ransforms key to hex and removes 'b' prefix
    key = binascii.b2a_hex(os.urandom(8)).decode("utf-8")

    # writes key to key.txt
    key_file = open("./data/key.txt", "w")
    key_file.write(key)
    key_file.close()

    print('---------Key Generation----------')
    print(key)

def encryption():
    # Reads from both the key.txt & plaintext.txt file 
    key = open("./data/key.txt", "r")
    key = key.read()
    plaintext = open("./data/plaintext.txt", "r")
    plaintext = plaintext.read()

    # Generates random base 16 key transforms key to hex and removes 'b' prefix
    iv = binascii.b2a_hex(os.urandom(8)).decode("utf-8")

    # writes key to iv.txt
    iv_file = open("./data/iv.txt", "w")
    iv_file.write(iv)
    iv_file.close()
    
    # Generates AES encryption in CBC Mode & multiplies by 16 to generate the 16 byte sized blocks needed for encryption
    cbc = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cbc.encrypt(plaintext*16)

    # # Generates AES encryption in ECB Mode & multiplies by 16 to generate the 16 byte sized blocks needed for encryption
    ecb = AES.new(key, AES.MODE_ECB, iv)
    ciphertext_ecb = ecb.encrypt(plaintext*16)
    ciphertext_ecb = ciphertext_ecb.hex()

    # Converting ciphertext to hex and writing to ciphertext.txt
    ciphertext = ciphertext.hex()
    ct_file = open("./data/ciphertext.txt", "w")
    ct_file.write(ciphertext)
    ct_file.close()

    print('---------Encryption CBC Mode----------')
    print(ciphertext)

    print('---------Encryption ECB Mode----------')
    print(ciphertext_ecb)
    return ciphertext_ecb



def decryption():
    # Reads from the key.txt, ciphertext.txt & iv.txt file 
    key = open("./data/key.txt", "r")
    key = key.read()
    iv = open("./data/iv.txt", "r")
    iv = iv.read()
    ciphertext = open("./data/ciphertext.txt", "r")
    ciphertext = ciphertext.read()

    # AES decryption in CBC Mode, Unhexlifys the ciphertext, returns it to original length, and removes the leading b
    cbc = AES.new(key, AES.MODE_CBC, iv)
    ciphertext =  binascii.unhexlify(ciphertext)
    result = cbc.decrypt(ciphertext)
    result = result[0: len(result)//16]
    result = result.decode("utf-8")

    # Generates AES encryption in ECB Mode, Unhexlifys the ciphertext and returns it to original length, 
    ecb = AES.new(key, AES.MODE_ECB, iv)
    ciphertext_ecb = encryption()
    ciphertext = binascii.unhexlify(ciphertext_ecb)
    result_ecb = ecb.decrypt(ciphertext_ecb)
    result_ecb = result[0: len(result_ecb)//16]

    # Writing to result.txt
    result_file = open("./data/result.txt", "w")
    result_file.write(result)
    result_file.close()
    
    print('---------Decryption CBC Mode----------')
    print(result)

    print('---------Decryption ECB Mode----------')
    print(result_ecb)

keyGen()
# start_time = time.time()
encryption()
# print("--- %s seconds (Encryption)---" % (time.time() - start_time))
# start_time = time.time()
decryption()
# print("--- %s seconds (Decryption)---" % (time.time() - start_time))





