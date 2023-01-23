from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

# Function returns an AES object with correct key, mode, iv, or nonce
def get_cipher_obj(key, mode, iv, nonce, pattern=False):
    # only used for pattern checking
    if pattern:
        return AES.new(key=key, mode=mode)

    if mode in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB]:
        cipher = AES.new(key=key, mode=mode, iv=iv)
    elif mode in [AES.MODE_CTR]:
        cipher = AES.new(key=key, mode=mode, initial_value=0, nonce=nonce)
    else:
        cipher = AES.new(key= key, mode= mode)
    return cipher

# Encrypt a plaintext based on mode
def encrypt(plaintext, cipher, mode):
    # Check if the mode requires padding
    if mode in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_ECB]:
        plaintext = pad(plaintext, AES.block_size)
    
    # encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext= plaintext)

    return ciphertext

# Decrypt a ciphertext based on mode
def decrypt(ciphertext, cipher, mode):
    # decrpyt the ciphertext
    plaintext = cipher.decrypt(ciphertext)

    # remove the pad if necessary
    if mode in [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_ECB]:
        plaintext = unpad(padded_data= plaintext, block_size= AES.block_size)

    return plaintext

# Function checks for pattern preservation of an aes mode
def checkPattern(plaintext, key, mode, iv, nonce):
    # encrypt the plaintext twice with the same key
    cipher = get_cipher_obj(key, mode, iv, nonce, pattern=True)
    c1 = encrypt(plaintext, cipher, mode)
    c2 = encrypt(plaintext, cipher, mode)

    return c1 == c2

# Fucntion check for error propagation of an aes mode
def checkError(plaintext, key, mode, iv, nonce):
    
    # helper function to write results file "error.txt"
    def writeToFile(x, y): 
        file = open("error.txt", "a+")
        file.write(f"Mode: {mode}\n")
        file.write(f"unmodified: {x}\n")
        file.write(f"modified: {y}\n\n")

    # encrypt the plaintext
    cipher = get_cipher_obj(key, mode, iv, nonce)
    ciphertext = encrypt(plaintext=plaintext, cipher=cipher, mode=mode)

    # modify a bit in the ciphertext
    modified_cipher = list(ciphertext)
    modified_cipher[18] = modified_cipher[18] ^ 13
    modified_cipher = bytes(modified_cipher)

    # decrypt both the unmodified and modified ciphertext
    cipher = get_cipher_obj(key, mode, iv, nonce)
    unmodified_decrypted = decrypt(ciphertext=ciphertext, cipher=cipher, mode=mode)
    modified_decrypted = decrypt(ciphertext=modified_cipher, cipher=cipher, mode=mode)
    
    writeToFile(unmodified_decrypted, modified_decrypted)

    # check if there is some part of the unmodified message in modified
    for x in str(unmodified_decrypted).split(): # get all words in decrypted
        if x in str(modified_decrypted).split(): # check against all words/components of modified
            return False # if there is a match that means that error propagation doesn't happen
    return True # by default return True

# Main function to run all tests and blah blah blah
def task2():
    # Generate random key, iv, and nonce needed for all modes to work correctly
    key = get_random_bytes(16)
    plaintext = b'My Name is Sal, nice to meet you :) ! Im almost done with lab!'
    iv = get_random_bytes(16)
    nonce = get_random_bytes(8)

    # print for aesthetics
    print(f"KEY: {key}")
    print(f"PLAINTEXT: {plaintext}\n")

    # list of all modes to test
    modes = [AES.MODE_ECB, AES.MODE_CBC, AES.MODE_CFB, AES.MODE_OFB, AES.MODE_CTR]
    
    # list of all mode names indexed to their integer value. This is purely for aesthetics
    mode_names = ["ECB", "CBC", "CFB", "", "OFB", "CTR"]

    print("\t| Pattern Preservation?\t|   Error Propagation?\t|")
    print("=========================================================")
    
    # test every mode
    for mode in modes:
        # test for pattern preservation
        pattern = checkPattern(plaintext=plaintext, key=key, mode=mode, iv=iv, nonce=nonce)
        
        # test for error propagation
        error = checkError(plaintext=plaintext, key=key, mode=mode, iv=iv, nonce=nonce)
        mode_name = mode_names[mode - 1]
        print(f"Mode {mode_name}| \t{pattern} \t\t|\t  {error}\t\t|")


if __name__ == "__main__":
    task2()