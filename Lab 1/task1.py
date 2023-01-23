from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# Function that encrypts a plaintext, with a 128-bit key with AES in ECB mode
# plaintext, key => ciphertext
def aesEncryption(plaintext, key, encryption_mode):
    # padding the plaintext to the correct length
    padded_plaintext = pad(data_to_pad=plaintext, block_size= AES.block_size)

    # create a new cipher object using AES in CBC mode
    cipher = AES.new(key= key, mode= encryption_mode)

    # encrypt the padded plaintext
    ciphertext = cipher.encrypt(plaintext=padded_plaintext)

    print("Ciphertext: ", base64.b64encode(ciphertext))
    return ciphertext

# Function that decrypts a plaintext, with a 128-bit key with AES in ECB mode
# ciphertext, key => plaintext
def aesDecryption(ciphertext, key, encryption_mode):
    cipher = AES.new(key= key, mode= encryption_mode)
    # decrypt the ciphertext
    plaintext = cipher.decrypt(ciphertext=ciphertext)

    # remove padding
    unpadded_plaintext = unpad(padded_data= plaintext, block_size= AES.block_size)

    print("Plaintext (Normal Decryption): ", unpadded_plaintext)

import itertools

# Function performs a brute force attack on a ciphertext, knowing only the length 
# of key, and encryption algorithm
# ciphertext, key_length => file of possible encryptions
def aesAttackDecryption(ciphertext, key_length, encryption_mode):
    keys = itertools.product(range(0, 256), repeat=key_length)
    file = open("messages.txt", "w+")
    for key in keys:
        print("Attacking with key: ", bytes(key))
        cipher = AES.new(key= bytes(key), mode= encryption_mode)
        # decrypt the ciphertext
        plaintext = cipher.decrypt(ciphertext=ciphertext)

        # remove padding
        try:
            plaintext = unpad(padded_data= plaintext, block_size= AES.block_size)
        except ValueError:
            continue
        
        file.write(str(plaintext) + "\n")
    

def task1AES():
    key = b'\xff' * 16
    plaintext = b'this is the wireless security lab'
    ecb = AES.MODE_ECB

    # Encrypt plaintext with a 128 bit key of 1s, with AES in ECB mode
    ciphertext = aesEncryption(plaintext= plaintext, key= key, encryption_mode= ecb)
    
    aesDecryption(ciphertext= ciphertext, key= key, encryption_mode= ecb)

    aesAttackDecryption(ciphertext=ciphertext, key_length=len(key), encryption_mode=ecb)

from Crypto.Cipher import ARC4

# Function that encrypts a plaintext, with a 40-bit key with RC4
# plaintext, key => ciphertext
def rc4Encryption(plaintext, key):
    # create a new RC4 cipher object
    cipher = ARC4.new(key)

    # encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext)

    print("Ciphertext (RC4): ", ciphertext)
    return ciphertext

# Function that decrypts a ciphertext, with a 40-bit key with RC4
# plaintext, key => ciphertext
def rc4Decryption(ciphertext, key):
    # create a new RC4 cipher object
    cipher = ARC4.new(key)

    # decrypt the ciphertext
    plaintext = cipher.decrypt(ciphertext)

    print("Plaintext (RC4 Normal Decryption): ", plaintext)

import cardinality

# Function performs a brute force attack on a ciphertext, knowing only the length 
# of key, and encryption algorithm
# ciphertext, key_length => file of possible encryptions
def rc4AttackDecryption(ciphertext, key_length):
    # Generate all possible keys
    keys = itertools.product(range(254, 256), repeat=key_length)

    # Open a file to store all messages
    file = open("rc4messages.txt", "w+")

    # Loop through all possible keys
    for i, key in enumerate(keys):
        # Get the bytes of the generated key
        key = bytes(key)
        
        # Used just for aesthetics
        percent = format(i / 1099511627776, '.2f')

        print(f"{percent}% | Attacking with key (RC4): {key}")

        # Create a new RC4 object with the generated key
        cipher = ARC4.new(key)

        # decrypt the iphertext
        plaintext = cipher.decrypt(ciphertext=ciphertext)

        # Write to file
        file.write(str(plaintext) + "\n")


def task1RC4():
    plaintext = b'this is the wireless security lab'
    key = b'\xff'*5

    ciphertext = rc4Encryption(plaintext=plaintext, key=key)
    
    # Normal decryption
    rc4Decryption(ciphertext=ciphertext, key=key)
    
    # Brute Force Decryption
    rc4AttackDecryption(ciphertext=ciphertext, key_length=len(key))

def main():
    #task1AES()
    task1RC4()


if __name__ == "__main__":
    main()