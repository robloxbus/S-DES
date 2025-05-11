import itertools
import time
import random
from itertools import product
import binascii

def permute(bits, perm):
    return ''.join(bits[i - 1] for i in perm)

def left_shift(bits, shifts):
    return bits[shifts:] + bits[:shifts]

def xor(bits1, bits2): 
    return ''.join(str(int(b1) ^ int(b2)) for b1, b2 in zip(bits1, bits2))

def bin_to_int(bits): #binary to integer
    return int(bits, 2)

def int_to_bin(value, length): #integer to binary
    return f"{value:0{length}b}"

def hex_to_bin(hex_str): # hexadecimal to binary
    return format(int(hex_str, 16), '08b')

def sbox_lookup(sbox, input_bits):
    row = int(input_bits[0] + input_bits[3], 2)
    col = int(input_bits[1] + input_bits[2], 2)
    return int_to_bin(sbox[row][col], 2)

def bin_to_hex(bin_str): # binary to hexadecimal
    return hex(int(bin_str, 2))[2:].zfill(2)

# As defined in the SDES documentation
class SDES:
    IP = [4, 8, 2, 7, 1, 5, 6, 3]  
    IP_INV = [5, 3, 8, 1, 6, 7, 4, 2]  
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    P4 = [2, 4, 3, 1]
    E = [4, 1, 2, 3, 2, 3, 4, 1]
    S1 = [
    [3, 2, 1, 0],
    [1, 0, 3, 2],
    [1, 3, 0, 2],
    [3, 2, 3, 1]
    ]
    S2 = [
    [2, 0, 1, 3],
    [2, 1, 0, 3],
    [0, 1, 2, 3],
    [3, 0, 1, 0]
    ]

    def __init__(self, key):
        self.key = int_to_bin(key, 10)  # Convert key to a 10-bit binary string
        self.subkeys = self.key_schedule()


    def set_key(self, key): #for DS-DES, update k1 and k2
        self.key = int_to_bin(int(key, 2), 10)  # Ensure key is 10-bit binary
        self.subkeys = self.key_schedule()
        
    def key_schedule(self):
        # PC-1 (Splitting into C and D parts)
        PC1_C = [8, 5, 4, 6, 10]  # First part for C0
        PC1_D = [3, 9, 1, 7, 2]   # Second part for D0
        
        #  PC-2 (Final subkey selection)
        PC2 = [9, 3, 8, 4, 7, 2, 10, 1]

        # Apply PC-1: Extract C0 and D0
        permuted_key = permute(self.key, PC1_C + PC1_D)  
        c, d = permuted_key[:5], permuted_key[5:]  # Split into C and D

        subkeys = []
        shift_pattern = [1, 2, 2, 2]  # Left shift values per round

        for shift in shift_pattern:
            c, d = left_shift(c, shift), left_shift(d, shift)  # Apply shifts
            subkeys.append(permute(c + d, PC2))  # Apply PC-2 to obtain subkey

        return subkeys

    def f_function(self, r, k):
        expanded_r = permute(r, self.E) # Expansion permutation to 8 bits
        xored = xor(expanded_r, k) # xor key with result of expansion
        left_sbox = sbox_lookup(self.S1, xored[:4]) # Left half to s1
        right_sbox = sbox_lookup(self.S2, xored[4:]) # Right half to s2
        return permute(left_sbox + right_sbox, self.P4) # Returns 4 bit with the permutation

    def encrypt(self, plaintext):
        # Apply initial permutation (IP)
        bits = permute(int_to_bin(plaintext, 8), self.IP)
        L, R = bits[:4], bits[4:]  # Split into left and right halves

        # 4 rounds
        for i in range(4):
            L_new = R  # L(i) = R(i-1)
            R_new = xor(L, self.f_function(R, self.subkeys[i]))  # R(i) = L(i-1) ⊕ f(R(i-1), K(i))
            L, R = L_new, R_new

        # Concatenate R4 and L4 before applying InvIP
        pre_output = R + L  
        bits = permute(pre_output, self.IP_INV)  # Apply inverse permutation
        return bin_to_int(bits)


    def decrypt(self, ciphertext):
        bits = permute(int_to_bin(ciphertext, 8), self.IP)  # Apply initial permutation
        L, R = bits[:4], bits[4:]  # Split into left and right halves

        # 4 rounds (reverse order of subkeys for decryption)
        for i in range(3, -1, -1):
            L_new = R
            R_new = xor(L, self.f_function(R, self.subkeys[i]))  
            L, R = L_new, R_new

        # Final permutation (IP_INV)
        pre_output = R + L 
        bits = permute(pre_output, self.IP_INV)
        return bin_to_int(bits)
    
        '''**********End of SDES class**********'''


'''*****Meet in the middle attack, brute force attack, Cipherblock Chaining Decryption, Weak Keys*****'''


def meet_in_the_middle_attack(plaintexts, ciphertexts):
    sdes = SDES(0b0000000000)  # Initialize SDES 
    possible_keys = [''.join(k) for k in product('01', repeat=10)]  # All possible 10-bit keys
    
    # Convert plaintexts and ciphertexts to binary
    plaintexts_bin = [bin(int(p, 16))[2:].zfill(8) for p in plaintexts]
    ciphertexts_bin = [bin(int(c, 16))[2:].zfill(8) for c in ciphertexts]
    
    # Step 1: Forward encryption (Plaintext -> Intermediate)
    forward_table = {}
    for k1 in possible_keys:
        sdes.set_key(k1)
        intermediate_set = set()
        for p in plaintexts_bin:
            intermediate = bin(sdes.encrypt(int(p, 2)))[2:].zfill(8)
            intermediate_set.add(intermediate)
        forward_table[k1] = intermediate_set

    # Step 2: Backward decryption (Ciphertext -> Intermediate) 
    backward_table = {}
    for k2 in possible_keys:
        sdes.set_key(k2)
        intermediate_set = set()
        for c in ciphertexts_bin:
            intermediate = bin(sdes.decrypt(int(c, 2)))[2:].zfill(8)
            intermediate_set.add(intermediate)
        backward_table[k2] = intermediate_set

    # Step 3: Compare intermediate values to find the matching keys
    for k1, f_intermediates in forward_table.items():
        for k2, b_intermediates in backward_table.items():
            common_intermediates = f_intermediates & b_intermediates  # Find common intermediate values
            if len(common_intermediates) == len(plaintexts):  # Ensure match for all pairs
                print(f"Found matching keys: k1 = {k1}, k2 = {k2}, common intermediates = {common_intermediates}")
                return k1, k2  # Return the key pair that works for all

    print("No matching key pair found.")
    return None

def brute_force_search(plaintexts, ciphertexts, tk1, tk2):
    sdes = SDES(0b0000000000)  # Placeholder SDES instance
    possible_keys = [''.join(k) for k in product('01', repeat=10)]  # Generate all 10-bit keys

    # Convert plaintexts and ciphertexts to binary
    plaintexts_bin = [bin(int(p, 16))[2:].zfill(8) for p in plaintexts]
    ciphertexts_bin = [bin(int(c, 16))[2:].zfill(8) for c in ciphertexts]

    # Convert target keys to indices
    index_k1 = possible_keys.index(tk1)
    index_k2 = possible_keys.index(tk2)

    start_time = time.time()

    # Iterate through all key pairs up to target keys
    for i in range(index_k1 + 1):  # k1 from 0 to target k1
        k1 = possible_keys[i]
        for j in range(index_k2 + 1):  # k2 from 0 to target k2
            k2 = possible_keys[j]

            # Encrypt using k1 and k2
            sdes.set_key(k1)
            intermediate_values = [bin(sdes.encrypt(int(p, 2)))[2:].zfill(8) for p in plaintexts_bin]

            sdes.set_key(k2)
            encrypted_values = [bin(sdes.encrypt(int(intermediate, 2)))[2:].zfill(8) for intermediate in intermediate_values]

            # Check if encrypted values match expected ciphertexts (binary comparison)
            if encrypted_values == ciphertexts_bin:
                end_time = time.time()
                elapsed_time = end_time - start_time
                print(f"Brute force found the key pair: k1 = {k1}, k2 = {k2}")
                print(f"Brute force execution time: {elapsed_time:.6f} seconds")
                return k1, k2

    print("Key not found within range.")
    return None

def decrypt_cbc(ciphertext_hex, k1, k2, iv):
    # Convert hex ciphertext to binary blocks
    ciphertext_bin = [bin(int(ciphertext_hex[i:i+2], 16))[2:].zfill(8) for i in range(0, len(ciphertext_hex), 2)]

    # Initialize SDES with dummy key (keys will be set later)
    sdes = SDES(0b0000000000)  

    # Convert IV to binary
    prev_cipher_block = bin(iv)[2:].zfill(8)

    decrypted_text = ""

    for cipher_block in ciphertext_bin:
        # Set SDES to k2 and decrypt first round
        sdes.set_key(k2)
        step1 = bin(sdes.decrypt(int(cipher_block, 2)))[2:].zfill(8)

        # Set SDES to k1 and decrypt second round
        sdes.set_key(k1)
        step2 = bin(sdes.decrypt(int(step1, 2)))[2:].zfill(8)

        # XOR with previous ciphertext block (IV for the first block)
        plaintext_bin = bin(int(step2, 2) ^ int(prev_cipher_block, 2))[2:].zfill(8)

        # Convert binary plaintext to ASCII character
        decrypted_text += chr(int(plaintext_bin, 2))

        # Update previous block for CBC chaining
        prev_cipher_block = cipher_block

    return decrypted_text

def find_weak_keys():
    weak_keys = []
    possible_keys = [''.join(k) for k in product('01', repeat=10)]  # Generate all 10-bit keys
    sdes = SDES(0b0000000000)  # Initialize SDES 

    for key in possible_keys:
        sdes.set_key(key)

        # Get the round keys (K1, K2)
        K1 = sdes.subkeys[0]
        K2 = sdes.subkeys[1]

        # Check if the round keys are the same 
        if K1 == K2:
            weak_keys.append(key)

    return weak_keys


'''Test functions'''


# Known Answer Tests
def run_tests():
    test_cases = [ #format [key, plaintext, ciphertext]
        (0b0000000000, 0b10000000, 0b00010111),
        (0b0000000000, 0b01000000, 0b11010001),
        (0b0000000000, 0b00100000, 0b00111101),
        (0b0001111101, 0b00000000, 0b01011001),
        (0b0000000001, 0b00000000, 0b01111001),
        (0b0010000100, 0b00000000, 0b11001010),
        (0b0000000000, 0b00000100, 0b10101011),
        (0b1000000000, 0b00000000, 0b11101010),
        (0b0000000101, 0b00000000, 0b00111111)
    ]
    for key, plaintext, expected_cipher in test_cases:
        # Test encryption with key on plaintext
        sdes = SDES(key)  # Initialize with the provided key

        cipher = sdes.encrypt(plaintext) 
        assert cipher == expected_cipher, f"Encryption failed: {plaintext:08b} -> {cipher:08b}, expected {expected_cipher:08b}"
       
        # Test decryption with the same key on the ciphertext
        decrypted_text = sdes.decrypt(cipher)
        assert decrypted_text == plaintext, f"Decryption failed: {cipher:08b} -> {decrypted_text:08b}, expected {plaintext:08b}"
    
    print("All known answer tests passed!")

#DSDES encryption/decryption functions for mitm testing
def two_des_encrypt(k1, k2, plain_text):
    sdes = SDES(k1)
    intermediate = sdes.encrypt(plain_text)
    sdes2 = SDES(k2)
    return sdes2.encrypt(intermediate)


def two_des_decrypt(k1, k2, cipher_text):
    sdes = SDES(k2)
    intermediate = sdes.decrypt(cipher_text)
    sdes2 = SDES(k1)
    return sdes2.decrypt(intermediate)

def run_tests_mitm():
    #found key that works with all pairs, hardcoded
    mitm_cases = [
        (0b1011100110, 0b1101000011, 0x42, 0x0f),
        (0b1011100110, 0b1101000011, 0x72, 0x85),
        (0b1011100110, 0b1101000011, 0x75, 0x3b),
        (0b1011100110, 0b1101000011, 0x74, 0x2e),
        (0b1011100110, 0b1101000011, 0x65, 0xed)
    ]
    
    for k1, k2, plaintext, expected_cipher in mitm_cases:
        final = two_des_encrypt(k1, k2, plaintext)
        print(f"Test case: K1 = {int_to_bin(k1, 10)}, K2 = {int_to_bin(k2, 10)}")
        print(f"  Plaintext:    {int_to_bin(plaintext, 8)}")
        print(f"  Expected:     {int_to_bin(expected_cipher, 8)}")
        print(f"  Final result: {int_to_bin(final, 8)}")
        assert final == expected_cipher, f"Test failed: expected {expected_cipher:08b}, got {final:08b}"
        print("  Test passed!\n")
    
    print("All MITM tests passed!")


'''  main  '''

if __name__ == "__main__":
    run_tests() # this tests SDES Algorithm  with known test pairs

    plaintexts = ["0x42", "0x72", "0x75", "0x74", "0x65"] 
    ciphertexts = ["0x0f", "0x85", "0x3b", "0x2e", "0xed"]

    start_time = time.time()
    key_pair = meet_in_the_middle_attack(plaintexts, ciphertexts) #time avg: 0.3 seconds
    end_time = time.time()

    if key_pair:
        print(f"Key pair found: k1 = {key_pair[0]}, k2 = {key_pair[1]}")
    else:
        print("No key pair found.")
    
    print(f"Time taken for MITM attack: {end_time - start_time:.4f} seconds")
    
    run_tests_mitm() #this tests that the found keys work for all plain/cipher pairs
    

    print("Brute force currently forcing...")
    brute_force_search(plaintexts, ciphertexts, key_pair[0], key_pair[1])    #last tested time: 125.76 seconds 
   

    ciphertext_hex = "aa7a211c558bc0cedb51887f5e98de4d315b8b78cb39cb598c6b54cd6b54d5ef25a464c24e55dde1e4b3c477723c406d37fc6e0599e9d24d907849cd391267b6e3fe25f516accfbe297b4540078563fc25d0dbefc6e04fee3818d60aeec460798ad78d"
    iv = 0xA6  #initialization vector for cbc

    decrypted_message = decrypt_cbc(ciphertext_hex, key_pair[0], key_pair[1], iv)
    print("Decrypted Message:", decrypted_message)

    weak_keys = find_weak_keys()
    print("Weak Keys Found:", weak_keys)
   
