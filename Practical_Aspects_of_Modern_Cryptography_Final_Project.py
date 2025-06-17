#Project by Tahim Bhuiya


import streamlit as st
import math
import random
import numpy as np


# Set the background color directly



# Greatest Common Divisor (gcd) Function
def gcd(a, b):
    # Ensure that 'a' is greater than or equal to 'b' by swapping if necessary
    if a < b:
        return gcd(b, a)
    
    # Base case: if 'b' divides 'a' exactly, then 'b' is the GCD
    elif a % b == 0:
        return b
    
    # Recursive case: apply Euclidean algorithm
    else:
        return gcd(b, a % b)



# Modular Exponentiation Function using the Square-and-Multiply Algorithm
def power(a, b, c):
    result = 1                # Initialize result to 1
    base = a % c              # Reduce base 'a' modulo 'c' to keep numbers small

    while b > 0:              # Loop while exponent 'b' is greater than 0
        if b % 2 == 1:        # If the current bit of 'b' is 1 (i.e., b is odd)
            result = (result * base) % c  # Multiply result by base modulo 'c'
        base = (base * base) % c          # Square the base modulo 'c'
        b //= 2               # Divide exponent 'b' by 2 (shift right)

    return result             # Return the final result of (a^b) mod c



# Generate Large Prime Number using Fermat Primality Test
# Generate a large prime number using Fermat's Primality Test
def generate_prime_fermat(bits):
    while True:
        # Generate a random odd integer with the specified number of bits
        p = random.getrandbits(bits)

        # Check if 'p' is odd and satisfies Fermat's little theorem for base 2
        # i.e., 2^(p-1) ≡ 1 mod p — a probabilistic test for primality
        if p % 2 != 0 and pow(2, p - 1, p) == 1:
            
            # Ensure the number has the exact bit length (avoid shorter primes)
            if p.bit_length() != bits:
                continue  # If too short, try again
            
            return p  # Return the candidate if it passes all checks



# Generate a generator for the multiplicative group of integers modulo p
def find_generator(p):
    # Try candidate generators starting from 2 up to p-1
    for g in range(2, p):
        # Check that g^((p-1)/2) mod p != 1 and g^((p-1)/3) mod p != 1
        # This ensures g is a primitive root mod p (not generating a smaller subgroup)
        if pow(g, (p - 1) // 2, p) != 1 and pow(g, (p - 1) // 3, p) != 1:
            return g  # Return the first suitable generator found

# Generate ElGamal asymmetric key pair
def generate_keys_elgamal(bits):
    q = generate_prime_fermat(bits)  # Generate a large prime q
    g = find_generator(q)             # Find a suitable generator g modulo q

    # Define private key range: choose a large private key roughly half the bit size of q
    min_private_key = 2 ** (bits // 2)
    max_private_key = q - 1
    private_key = random.randint(min_private_key, max_private_key)  # Random private key in range

    public_key = power(g, private_key, q)  # Compute public key: g^private_key mod q
    return q, g, private_key, public_key  # Return all parameters

# ElGamal encryption of a plaintext message string
def encrypt_elgamal(msg, q, g, public_key):
    ciphertext = []
    for char in msg:
        k = random.randint(2, q - 1)       # Choose random ephemeral key k
        s = power(public_key, k, q)        # Compute shared secret s = (public_key)^k mod q
        # Append ciphertext pair: (g^k mod q, (char * s) mod q)
        ciphertext.append((power(g, k, q), (ord(char) * s) % q))
    return ciphertext

# ElGamal decryption of ciphertext pairs
def decrypt_elgamal(ciphertext, q, private_key):
    decrypted_message = ''
    for c1, c2 in ciphertext:
        h = pow(c1, private_key, q)         # Compute shared secret h = c1^private_key mod q
        h_inv = pow(h, -1, q)               # Compute modular inverse of h modulo q
        decrypted_char = chr((c2 * h_inv) % q)  # Recover original character from ciphertext
        decrypted_message += decrypted_char # Append to decrypted message string
    return decrypted_message


























key_des = np.zeros(64, dtype=int)            # Key for encryption/decryption
sub_key_des = np.zeros((16, 48), dtype=int)   # Array to store 16 subkeys

# Initial Permutation (IP) table
ip_des = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9,  1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final Permutation (IP^-1) table
ip_1_des = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41,  9, 49, 17, 57, 25]

# Permuted Choice 1 (PC-1) table for key schedule
pc_1_des = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4]

# Permuted Choice 2 (PC-2) table for key schedule
pc_2_des = [14, 17, 11, 24,  1,  5,
        3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32]

# Number of left shifts for each round key
shift_bits_des = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# Expansion table for the round function
e_des = [32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1]

# S-boxes for the round function
s_box_des = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# Permutation table for the round function
p_des = [16,  7, 20, 21,
     29, 12, 28, 17,
      1, 15, 23, 26,
      5, 18, 31, 10,
      2,  8, 24, 14,
     32, 27,  3,  9,
     19, 13, 30,  6,
     22, 11,  4, 25]


def f_des(r, k):
    # Create a 48-bit array initialized to zeros to hold the expanded R
    expand_r = np.zeros(48, dtype=int)

    # Expansion permutation: Expand 32-bit input R to 48 bits using the E-table (e_des)
    # and reverse the index to match bit ordering
    for i in range(48):
        expand_r[47 - i] = r[32 - e_des[i]]

    # XOR the expanded R with the 48-bit round key K
    expand_r = expand_r ^ k

    # Prepare a 32-bit array for the output of the S-box substitutions
    output = np.zeros(32, dtype=int)
    x = 0

    # Apply S-box substitution for each of the 8 S-boxes (6 bits each)
    for i in range(0, 48, 6):
        # Calculate row (using first and last bit of the 6-bit group)
        row = expand_r[47 - i] * 2 + expand_r[47 - i - 5]

        # Calculate column (using the middle 4 bits)
        col = expand_r[47 - i - 1] * 8 + expand_r[47 - i - 2] * 4 + expand_r[47 - i - 3] * 2 + expand_r[47 - i - 4]

        # Lookup value from corresponding S-box
        num = s_box_des[i // 6][row][col]

        # Convert the result to 4-bit binary
        binary = [int(x) for x in format(num, '04b')]

        # Store the 4-bit output in the correct position in the output array (reverse order)
        output[31 - x] = binary[3]
        output[31 - x - 1] = binary[2]
        output[31 - x - 2] = binary[1]
        output[31 - x - 3] = binary[0]
        x += 4

    # Copy output to temporary array before final permutation
    temp = output.copy()

    # Final 32-bit permutation using P-table (p_des)
    for i in range(32):
        output[31 - i] = temp[32 - p_des[i]]

    # Return the final 32-bit output after S-box substitution and permutation
    return output


def left_shift_des(k, shift):
    # Make a copy of the input array `k` (expected to be 28 bits)
    temp = k.copy()

    # Perform a circular left shift by `shift` positions
    # This loop goes from the most significant bit (index 27) down to 0
    for i in range(27, -1, -1):
        # If shifting past the beginning of the array, wrap around from the end
        if i - shift < 0:
            k[i] = temp[i - shift + 28]
        else:
            k[i] = temp[i - shift]

    # Return the left-shifted array
    return k



def generate_keys_des():
    global key_des, sub_key_des  # key_des: 64-bit original key, sub_key_des: array to store 16 round keys

    # Initialize arrays for key processing
    key_real = np.zeros(56, dtype=int)     # 56-bit key after PC-1 permutation
    left = np.zeros(28, dtype=int)         # Left half of key (28 bits)
    right = np.zeros(28, dtype=int)        # Right half of key (28 bits)
    key_compress = np.zeros(48, dtype=int) # Final 48-bit subkey for each round

    # Apply the PC-1 permutation to the original 64-bit key to produce a 56-bit key
    for i in range(56):
        key_real[55 - i] = key_des[64 - pc_1_des[i]]

    # Generate 16 round keys
    for round in range(16):
        # Split the 56-bit key into left and right 28-bit halves
        for i in range(28, 56):
            left[i - 28] = key_real[i]
        for i in range(28):
            right[i] = key_real[i]

        # Perform left circular shift on both halves according to the round's shift amount
        left = left_shift_des(left, shift_bits_des[round])
        right = left_shift_des(right, shift_bits_des[round])

        # Merge the shifted halves back into key_real
        for i in range(28, 56):
            key_real[i] = left[i - 28]
        for i in range(28):
            key_real[i] = right[i]

        # Apply PC-2 permutation to reduce the 56-bit combined key to 48 bits
        for i in range(48):
            key_compress[47 - i] = key_real[56 - pc_2_des[i]]

        # Store the 48-bit subkey for this round
        sub_key_des[round] = key_compress




def char_to_bitset(s):
    # Initialize a 64-bit array (as integers) to store the bit representation of the input string
    bits = np.zeros(64, dtype=int)

    # Convert each of the 8 characters in the string to 8 bits (total 64 bits)
    for i in range(8):  # Loop over each character (assumed to be 8 characters long)
        for j in range(8):  # Loop over each bit (0–7) in the character
            # Extract the j-th bit of character s[i] using bit shifting and bitwise AND
            bits[i * 8 + j] = (s[i] >> j) & 1

    # Return the 64-bit array representing the entire string
    return bits



def bitset_to_string(bit):
    res = b""  # Initialize an empty byte string to store the result

    # Loop over each of the 8 bytes (8 * 8 = 64 bits total)
    for i in range(8):
        c = 0x00  # Start with 0 for the current character

        # Process 8 bits for the current byte, from most significant to least significant bit
        for j in range(7, -1, -1):
            c = c + bit[i * 8 + j]  # Add the current bit (0 or 1)
            if j != 0:
                c = c * 2  # Left shift (multiply by 2), except after the last bit

        # Convert the constructed byte to a single-byte and append it to the result
        res += bytes([c])

    return res  # Return the final 8-byte string



    
    
    
    
# Function to pad plaintext to a multiple of block size (64 bits or 8 bytes)
def pad_plaintext(plaintext):
    # Calculate how many bytes of padding are needed (between 1 and 8)
    padding_len = 8 - len(plaintext) % 8

    # Create the padding: a sequence of bytes, each equal to the padding length (PKCS#5/PKCS#7 style)
    padding = bytes([padding_len]) * padding_len

    # Append the padding to the original plaintext and return
    return plaintext + padding


# Function to split plaintext into 64-bit (8-byte) blocks and convert each to a bitset
def split_blocks(plaintext):
    blocks = []  # Initialize list to hold the blocks

    # Iterate over the plaintext in 8-byte steps
    for i in range(0, len(plaintext), 8):
        block = plaintext[i:i+8]  # Extract an 8-byte block
        blocks.append(char_to_bitset(block))  # Convert block to 64-bit array and add to list

    return blocks  # Return list of 64-bit bitset blocks


# Function to merge 64-bit bitset blocks back into a single byte string
def merge_blocks(blocks):
    plaintext = b""  # Initialize an empty byte string to store the result

    # Iterate through each 64-bit block
    for block in blocks:
        # Convert the 64-bit bit array back into an 8-byte string and append it
        plaintext += bitset_to_string(block)

    return plaintext  # Return the reconstructed plaintext

    

# Function to encrypt plaintext of any size using DES
def encrypt_des(plaintext, key):
    global sub_key_des  # Use global key schedule variable (used by DES rounds)

    # Step 1: Pad plaintext to make its length a multiple of 64 bits (8 bytes)
    blocks = split_blocks(pad_plaintext(plaintext))

    ciphertext_blocks = []

    # Step 2: Encrypt each 64-bit block individually
    for block in blocks:
        generate_keys_des()  # Generate round keys (assumes key is set globally)
        ciphertext_block = encrypt_des_block(block, key_des)  # Encrypt the block with DES
        ciphertext_blocks.append(ciphertext_block)  # Store the encrypted block

    # Step 3: Merge all encrypted blocks into the final ciphertext
    return merge_blocks(ciphertext_blocks)


# Function to decrypt ciphertext of any size using DES
def decrypt_des(ciphertext, key):
    global sub_key_des  # Use global key schedule variable (used by DES rounds)

    # Step 1: Split the ciphertext into 64-bit (8-byte) blocks
    blocks = split_blocks(ciphertext)

    plaintext_blocks = []

    # Step 2: Decrypt each 64-bit block individually
    for block in blocks:
        generate_keys_des()  # Generate round keys (assumes key is set globally)
        plaintext_block = decrypt_des_block(block, key_des)  # Decrypt the block with DES
        plaintext_blocks.append(plaintext_block)  # Store the decrypted block

    # Step 3: Merge all decrypted blocks into the final plaintext
    # Strip padding zeros added during encryption
    return merge_blocks(plaintext_blocks).rstrip(bytes([0]))


# Modify the encryption and decryption functions to operate on single blocks
# Modify the encryption and decryption functions to operate on single 64-bit blocks
def encrypt_des_block(plain, key):
    global sub_key_des  # Use globally stored round subkeys

    # Initialize arrays to store bits
    cipher = np.zeros(64, dtype=int)        # Final ciphertext block (64 bits)
    current_bits = np.zeros(64, dtype=int)  # Intermediate state during permutation
    left = np.zeros(32, dtype=int)          # Left 32 bits
    right = np.zeros(32, dtype=int)         # Right 32 bits
    new_left = np.zeros(32, dtype=int)      # Temporary holder for new left half

    # Step 1: Initial permutation (IP)
    for i in range(64):
        current_bits[63 - i] = plain[64 - ip_des[i]]

    # Step 2: Split 64-bit block into two 32-bit halves
    for i in range(32, 64):
        left[i - 32] = current_bits[i]
    for i in range(32):
        right[i] = current_bits[i]

    # Step 3: Perform 16 DES rounds
    for round in range(16):
        new_left = right.copy()  # Store current right half as new left
        # Apply the DES round function f to the right half and current subkey
        right = left ^ f_des(right, sub_key_des[round])
        left = new_left  # Update left half

    # Step 4: Combine left and right halves (note the swap after the final round)
    for i in range(32):
        cipher[i] = left[i]
    for i in range(32, 64):
        cipher[i] = right[i - 32]

    # Step 5: Final permutation (IP⁻¹)
    current_bits = cipher.copy()
    for i in range(64):
        cipher[63 - i] = current_bits[64 - ip_1_des[i]]

    return cipher  # Return the encrypted 64-bit block


# Function to decrypt a single 64-bit block using DES
def decrypt_des_block(cipher, key):
    global sub_key_des  # Use globally stored subkeys (generated beforehand)

    # Initialize arrays to store intermediate and final values
    plain = np.zeros(64, dtype=int)         # Final decrypted plaintext block (64 bits)
    current_bits = np.zeros(64, dtype=int)  # Intermediate state after initial permutation
    left = np.zeros(32, dtype=int)          # Left 32-bit half
    right = np.zeros(32, dtype=int)         # Right 32-bit half
    new_left = np.zeros(32, dtype=int)      # Temporary holder for new left half

    # Step 1: Initial permutation (IP) on the ciphertext block
    for i in range(64):
        current_bits[63 - i] = cipher[64 - ip_des[i]]

    # Step 2: Split 64-bit block into left and right 32-bit halves
    for i in range(32, 64):
        left[i - 32] = current_bits[i]
    for i in range(32):
        right[i] = current_bits[i]

    # Step 3: Perform 16 DES rounds in reverse order (decryption)
    for round in range(15, -1, -1):  # Iterate from round 15 down to 0
        new_left = right.copy()  # Save current right half as new left
        # Apply DES round function with corresponding subkey
        right = left ^ f_des(right, sub_key_des[round])
        left = new_left  # Update left half

    # Step 4: Combine the left and right halves (note the final swap)
    for i in range(32):
        plain[i] = left[i]
    for i in range(32, 64):
        plain[i] = right[i - 32]

    # Step 5: Final permutation (IP⁻¹) to get the original plaintext block
    current_bits = plain.copy()
    for i in range(64):
        plain[63 - i] = current_bits[64 - ip_1_des[i]]

    return plain  # Return the decrypted 64-bit block




# Function to perform Triple DES (3DES) encryption
def encrypt_3des(plaintext, key1, key2, key3):
    # Step 1: Encrypt the plaintext with the first key (K1)
    intermediate_cipher = encrypt_des(plaintext, key1)

    # Step 2: Decrypt the result with the second key (K2)
    # This unusual decryption step is part of the EDE (Encrypt-Decrypt-Encrypt) 3DES scheme
    decrypted_intermediate = decrypt_des(intermediate_cipher, key2)
    decrypted_intermediate = remove_padding(decrypted_intermediate)  # Clean any padding if applied during intermediate DES steps

    # Step 3: Encrypt the result again with the third key (K3)
    final_cipher = encrypt_des(decrypted_intermediate, key3)

    # Return the final ciphertext after 3DES processing
    return final_cipher



# Function to perform Triple DES (3DES) decryption
def decrypt_3des(cipher_text, key1, key2, key3):
    # Step 1: Decrypt the ciphertext with the third key (K3)
    # This reverses the last encryption step in 3DES encryption
    intermediate_plain_text = decrypt_des(cipher_text, key3)
    intermediate_plain_text = remove_padding(intermediate_plain_text)  # Clean up any padding if present

    # Step 2: Encrypt the result with the second key (K2)
    # This reverses the second step of EDE (Encrypt-Decrypt-Encrypt)
    intermediate_cipher_text = encrypt_des(intermediate_plain_text, key2)

    # Step 3: Decrypt the result with the first key (K1)
    # This undoes the initial encryption in the 3DES process
    plain_text = decrypt_des(intermediate_cipher_text, key1)

    # Final step: Remove padding to retrieve original plaintext
    plain_text = remove_padding(plain_text)
    
    return plain_text












# Function to perform the Extended Euclidean Algorithm
def extended_euclidean(a, b):
    """
    Computes the greatest common divisor (gcd) of a and b,
    as well as integers x and y such that:
        ax + by = gcd(a, b)
    This is useful for computing modular inverses and solving Diophantine equations.
    """
    # Base case: if b is 0, then gcd is a and the coefficients are (1, 0)
    if b == 0:
        return a, 1, 0
    else:
        # Recursive call: compute gcd and coefficients for (b, a % b)
        gcd, x, y = extended_euclidean(b, a % b)

        # Update coefficients using the recursion relation
        return gcd, y, x - (a // b) * y


# Function to compute the modular inverse of a modulo m
def modular_inverse(a, m):
    """
    Computes the modular inverse of a modulo m using the Extended Euclidean Algorithm.
    The modular inverse is a value x such that:
        (a * x) % m == 1

    Raises a ValueError if the inverse does not exist (i.e., a and m are not coprime).
    """
    gcd, x, _ = extended_euclidean(a, m)  # Get gcd and the coefficient x such that ax + my = gcd(a, m)

    # If gcd is not 1, inverse does not exist
    if gcd != 1:
        raise ValueError(f"{a} has no inverse modulo {m}")

    # Ensure the result is in the range [0, m-1]
    return x % m


# Function to generate a prime number of specified bit length that is congruent to 3 mod 4
def generate_prime_congruent_3_mod_4(bit_length):
    """
    Generates a random prime number of the given bit length such that:
        prime ≡ 3 (mod 4)
    This condition is often required in cryptographic algorithms such as Blum Blum Shub
    and Blum-Goldwasser.

    Parameters:
        bit_length (int): Desired bit length of the prime number.

    Returns:
        int: A prime number of the given bit length where prime % 4 == 3.
    """
    while True:
        # Generate a random number in the desired bit range
        prime = random.randint(2**(bit_length - 1), 2**bit_length - 1)

        # Check if it satisfies the congruence and primality conditions
        if prime % 4 == 3 and is_prime(prime):
            return prime


# Function to generate Blum-Goldwasser key components
def generate_blum_goldwasser(bit_length):
    """
    Generates a Blum integer N = p * q, where both p and q are distinct prime numbers
    congruent to 3 modulo 4. This structure is essential for the Blum-Goldwasser cryptosystem.

    Parameters:
        bit_length (int): Bit length of each prime (p and q).

    Returns:
        tuple: (p, q, N) where N = p * q and both p, q ≡ 3 mod 4
    """
    while True:
        # Generate two distinct primes p and q such that p ≡ q ≡ 3 mod 4
        p = generate_prime_congruent_3_mod_4(bit_length)
        q = generate_prime_congruent_3_mod_4(bit_length)

        # Ensure p and q are different to avoid a weak modulus
        if p != q:
            return p, q, p * q  # Return the primes and their product N


# Function to perform the Miller-Rabin primality test
def is_prime(n, k=5):
    """
    Determines whether a number n is probably prime using the Miller-Rabin primality test.

    Parameters:
        n (int): The number to test for primality.
        k (int): The number of iterations (witnesses) to improve accuracy (default is 5).

    Returns:
        bool: True if n is probably prime, False if composite.
    """
    # Handle small base cases directly
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # Write n-1 as 2^r * d where d is odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Perform k iterations (random witnesses)
    for _ in range(k):
        a = random.randint(2, n - 2)  # Choose a random base in [2, n-2]
        x = pow(a, d, n)  # Compute a^d mod n

        if x == 1 or x == n - 1:
            continue  # Probably prime for this witness

        # Square x up to r-1 times and check for non-trivial square roots of 1
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # Composite

    return True  # Probably prime


# Function to encrypt a binary message using the Blum-Goldwasser cryptosystem
def blum_goldwasser_encrypt(m, N):
    """
    Encrypts the binary plaintext `m` using the Blum-Goldwasser probabilistic public-key encryption scheme.

    Parameters:
        m (list of int): The binary plaintext message (list of 0s and 1s).
        N (int): The public key (a Blum integer, i.e., N = p * q where p ≡ q ≡ 3 mod 4).

    Returns:
        tuple:
            - cipher (list of int): The encrypted binary message (ciphertext).
            - initial_seed (int): The initial seed used, needed for decryption.
    """
    message_length = len(m)  # Determine the number of bits in the plaintext

    # Choose a random seed in the range [2, N-1] to start the pseudorandom sequence
    initial_seed = random.randint(2, N - 1)

    encoded_message = []      # To store the pseudorandom bit stream
    current_seed = initial_seed

    # Generate one pseudorandom bit for each bit of the message
    for _ in range(message_length):
        encoded_message.insert(0, current_seed & 1)  # Take the least significant bit of the seed
        current_seed = (current_seed * current_seed) % N  # Update the seed using squaring modulo N

    # XOR each bit of the message with the pseudorandom bit stream to get the ciphertext
    cipher = [(m[i] ^ encoded_message[i]) for i in range(message_length)]

    return cipher, initial_seed  # Return the ciphertext and the seed used for decryption


# Function to decrypt a binary message using the Blum-Goldwasser cryptosystem
def blum_goldwasser_decrypt(cipher, initial_seed, N, message_length, p, q, a, b):
    """
    Decrypts the ciphertext using the Blum-Goldwasser decryption scheme.

    Parameters:
        cipher (list of int): The encrypted binary message (ciphertext).
        initial_seed (int): The final seed sent by the sender (used to reconstruct the pseudorandom sequence).
        N (int): The Blum modulus N = p * q.
        message_length (int): Length of the original message.
        p (int): First prime factor of N (p ≡ 3 mod 4).
        q (int): Second prime factor of N (q ≡ 3 mod 4).
        a (int): Precomputed coefficient for CRT (usually q * modular_inverse(q, p)).
        b (int): Precomputed coefficient for CRT (usually p * modular_inverse(p, q)).

    Returns:
        list of int: The decrypted binary message (plaintext).
    """

    current_seed = initial_seed
    decoded_message = []

    # Reconstruct the pseudorandom bit stream in reverse
    for _ in range(message_length):
        decoded_message.insert(0, current_seed & 1)  # Extract the LSB
        current_seed = (current_seed * current_seed) % N  # Reverse iteration not done here

    # XOR the ciphertext with the pseudorandom bits to recover plaintext
    plaintext = [(cipher[i] ^ decoded_message[i]) for i in range(message_length)]

    return plaintext




# Wrapper function to encrypt a plaintext message using Blum-Goldwasser
def bg_encrypt_message(plaintext, public_key):
    """
    Encrypts a binary plaintext message using the Blum-Goldwasser cryptosystem.

    Parameters:
        plaintext (list of int): The binary plaintext message (e.g., list of 0s and 1s).
        public_key (int): The Blum public key N = p * q, where both p and q ≡ 3 mod 4.

    Returns:
        tuple:
            - cipher (list of int): The encrypted binary message.
            - initial_seed (int): The initial seed used for pseudorandom bit generation (needed for decryption).
    """
    cipher, initial_seed = blum_goldwasser_encrypt(plaintext, public_key)
    return cipher, initial_seed


# Function to decrypt ciphertext using Blum-Goldwasser
def bg_decrypt_message(ciphertext, initial_seed, public_key, private_key):
    """
    Decrypts a ciphertext encrypted with the Blum-Goldwasser cryptosystem.

    Parameters:
        ciphertext (list of int): The binary encrypted message (ciphertext).
        initial_seed (int): The seed used during encryption (sent alongside the ciphertext).
        public_key (int): The Blum modulus N = p * q.
        private_key (tuple): A tuple (p, q, a, b) where:
            - p, q are the primes such that N = p * q,
            - a = q * modular_inverse(q, p),
            - b = p * modular_inverse(p, q) — for CRT reconstruction.

    Returns:
        list of int: The decrypted binary message (plaintext).
    """
    plaintext = blum_goldwasser_decrypt(
        ciphertext,
        initial_seed,
        public_key,
        len(ciphertext),
        *private_key  # Unpacks p, q, a, b
    )
    return plaintext





# Function to generate keys for the Blum-Goldwasser cryptosystem
def generate_bg_keys(bit_length):
    """
    Generates the key components needed for Blum-Goldwasser encryption and decryption.

    Parameters:
        bit_length (int): The bit length of each prime number p and q to be generated.

    Returns:
        tuple:
            - p (int): A prime congruent to 3 mod 4.
            - q (int): Another prime congruent to 3 mod 4, distinct from p.
            - a (int): Coefficient used for CRT recombination (solves a*p + b*q = gcd(p, q)).
            - b (int): Coefficient used for CRT recombination.
            - N (int): The public modulus N = p * q.
    """
    # Generate two distinct primes p and q, each congruent to 3 mod 4
    p, q, N = generate_blum_goldwasser(bit_length)

    # Compute the modular inverses of p and q (not directly used here but useful)
    p_inverse = modular_inverse(p, q)
    q_inverse = modular_inverse(q, p)

    # Use Extended Euclidean Algorithm to find a and b such that a*p + b*q = gcd(p, q)
    gcd, a, b = extended_euclidean(p, q)

    # Adjust coefficients to ensure a is positive
    if a < 0:
        a += q
        b -= p

    return p, q, a, b, N





# Function to remove padding from decrypted data
def remove_padding(data):
    """
    Removes PKCS#7-style padding from the end of the byte data.

    Parameters:
        data (bytes or bytearray): The padded data.

    Returns:
        bytes or bytearray: The original unpadded data.
    """
    padding_len = data[-1]  # Last byte indicates the number of padding bytes added
    return data[:-padding_len]  # Remove the padding


















# Streamlit interface
st.title("Practical Aspects of Modern Cryptography Final Project")

# Ask user to select encryption scheme
encryption_scheme = st.radio("Select Encryption Scheme:", ("ElGamal", "DES", "3DES","Blum-Goldwasser", "Elgamal and DES (Hybrid)","Elgamal and 3DES (Hybrid)"))

if encryption_scheme == "ElGamal":
    
    # ElGamal Encryption Section
    st.title("ElGamal Key Generation")

    # Get Key Size from User for Encryption
    key_size = st.number_input("Enter the key size in bits (preferably 16, 32, 64, 128, 256): ", min_value=1, value=16, key="elgamal_key_size_enc")

    if st.button("Generate Keys"):
        q, g, private_key, public_key = generate_keys_elgamal(key_size)
        st.session_state['elgamal_q'] = q
        st.session_state['elgamal_g'] = g
        st.session_state['elgamal_private_key'] = private_key
        st.session_state['elgamal_public_key'] = public_key
        st.success("Keys generated successfully!")

    if 'elgamal_q' in st.session_state:
        st.write("Prime Number (q):", st.session_state['elgamal_q'])
    if 'elgamal_g' in st.session_state:
        st.write("Generator (g):", st.session_state['elgamal_g'])
    if 'elgamal_public_key' in st.session_state:
        st.write("Public Key:", st.session_state['elgamal_public_key'])
    if 'elgamal_private_key' in st.session_state:
        st.write("Private Key (keep this secret!):", st.session_state['elgamal_private_key'])

    st.title("ElGamal Encryption (Asymmetric)")

    plaintext = st.text_input("Enter the plaintext message:", key="elgamal_plaintext_enc")
    encrypt_button = st.button("Encrypt Message")

    if encrypt_button and plaintext:
        if 'elgamal_q' in st.session_state and 'elgamal_g' in st.session_state and 'elgamal_public_key' in st.session_state:
            ciphertext = encrypt_elgamal(plaintext, st.session_state['elgamal_q'], st.session_state['elgamal_g'], st.session_state['elgamal_public_key'])
            st.write("Encrypted Message:")
            for pair in ciphertext:
                st.write(f"({pair[0]}, {pair[1]})")
        else:
            st.error("Please generate keys before encryption")

    # ElGamal Decryption Section
    st.title("ElGamal Decryption")

    # Prompt the user to enter the ciphertext
    ciphertext_input = st.text_area("Enter the ciphertext (as ordered pairs separated by commas, e.g., (123,456),(789,012)):", height=200, key="elgamal_ciphertext_dec")

    def parse_ciphertext_input(ciphertext_str):
        """
    Parses a string of ciphertext pairs into a list of tuples.

    Parameters:
        ciphertext_str (str): The input string from the user, e.g., "(123,456),(789,012)"

    Returns:
        list of tuples: Parsed ciphertext pairs [(123,456), (789,012), ...]
    """
        try:
            tuple_strs = ciphertext_str.replace(' ', '').split('),(')
            tuple_strs[0] = tuple_strs[0].lstrip('(')
            tuple_strs[-1] = tuple_strs[-1].rstrip(')')
            tuples = [tuple(map(int, t.split(','))) for t in tuple_strs]
            return tuples
        except ValueError:
            return []

    ciphertext = parse_ciphertext_input(ciphertext_input)

   

# Prompt the user to enter the prime number (q) as a string
    q_dec_str = st.text_input("Enter prime number (q):")

# Convert the input string to an integer if it's not empty
    q_dec = int(q_dec_str) if q_dec_str.strip() else None
    
    
# Prompt the user to enter the private key as a string
    private_key_dec_str = st.text_input("Enter your private key:")

# Convert the input string to an integer if it's not empty
    private_key_dec = int(private_key_dec_str) if private_key_dec_str.strip() else None
    
    decrypt_button = st.button("Decrypt Ciphertext")

    if decrypt_button and ciphertext and q_dec and private_key_dec:
        try:
            decrypted_message = decrypt_elgamal(ciphertext, q_dec, private_key_dec)
            st.write("Decrypted Message:", decrypted_message)
        except Exception:
            st.error("An error occurred during decryption.")

# If DES is selected from the encryption scheme options
elif encryption_scheme == "DES":
    # Title for DES section
    st.title("DES Encryption (Symmetric)")

    # Prompt user to enter a DES key (must be 8 characters = 64 bits)
    key_input = st.text_input("Enter the DES key (8 characters):", key="des_key")

    # Prompt user to enter the plaintext message to encrypt
    plaintext_input = st.text_input("Enter the plaintext message:", key="des_plaintext")

    # Button to trigger encryption
    encrypt_button = st.button("Encrypt")

    # Perform encryption only if key and plaintext are both provided
    if encrypt_button and key_input and plaintext_input:
        # Validate that the key is exactly 8 characters long
        if len(key_input) != 8:
            st.error("Error: Key must be 8 characters.")
        else:
            # Call the DES encryption function
            cipher_text = encrypt_des(plaintext_input.encode(), key_input.encode())

            # Display the resulting ciphertext in binary format for readability
            st.write("Cipher Text in Binary:")
            st.write(''.join(format(byte, '08b') for byte in cipher_text))


            

          

    # Decryption button
    # Key input
    # Decryption button
        # Key input
    # Title for DES decryption section
    st.title("DES Decryption")
    
    # Input for DES key (must be 8 characters long)
    key_input = st.text_input("Enter the DES key (8 characters):", key="des_key_input")
    
    # Input for the ciphertext in binary format (i.e., 64-bit multiple string like '01010101...')
    ciphertext_input = st.text_input("Enter the ciphertext (in binary):", key="des_ciphertext_input")
    
    # Button to trigger decryption
    decrypt_button = st.button("Decrypt")
    
    # Decrypt only when button is pressed and both fields are filled
    if decrypt_button and key_input and ciphertext_input:
        # Check if the key is valid length
        if len(key_input) != 8:
            st.error("Error: Key must be 8 characters.")
        else:
            try:
                # Convert binary string to bytes
                ciphertext = int(ciphertext_input, 2).to_bytes(len(ciphertext_input) // 8, byteorder='big')
            except ValueError:
                # If binary string is invalid
                st.error("Error: Ciphertext must be in binary format.")
                st.stop()
    
            # Ensure ciphertext length is a multiple of 64 bits (8 bytes)
            if len(ciphertext) % 8 != 0 or len(key_input) != 8:
                st.error("Error: Ciphertext must be a multiple of 64 bits and the key must be 8 characters.")
                st.stop()
            else:
                # Perform DES decryption
                plain_text = decrypt_des(ciphertext, key_input.encode())
    
                # Remove padding added during encryption (typically PKCS#7 style)
                padding_len = plain_text[-1]
                decrypted_plain_text = plain_text[:-padding_len]
    
                # Display decrypted message as a UTF-8 string
                st.write("Decrypted Plain Text:", decrypted_plain_text.decode())






elif encryption_scheme == "3DES":
    # 3DES Encryption Section
    st.title("Triple DES Encryption (Symmetric)")

    # Prompt user for three 8-character DES keys
    key1_input = st.text_input("Enter the first DES key (8 characters):", key="des_key1_enc")
    key2_input = st.text_input("Enter the second DES key (8 characters):", key="des_key2_enc")
    key3_input = st.text_input("Enter the third DES key (8 characters):", key="des_key3_enc")

    # Prompt user to enter plaintext to encrypt
    plaintext_input_3des = st.text_input("Enter the plaintext message:", key="3des_plaintext_enc")

    # Encryption button
    encrypt_button_3des = st.button("Encrypt (3DES)")

    # Proceed only if all fields are filled
    if encrypt_button_3des and key1_input and key2_input and key3_input and plaintext_input_3des:
        # Validate all keys are exactly 8 characters long
        if len(key1_input) != 8 or len(key2_input) != 8 or len(key3_input) != 8:
            st.error("Error: Keys must be 8 characters (64 bits) each.")
        else:
            # Encrypt the plaintext using 3DES (Encrypt-Decrypt-Encrypt with 3 different keys)
            cipher_text_3des = encrypt_3des(
                plaintext_input_3des.encode(), 
                key1_input.encode(), 
                key2_input.encode(), 
                key3_input.encode()
            )

            # Display the encrypted ciphertext in binary format
            st.write("Cipher Text for 3DES (binary):")
            st.write(''.join(format(byte, '08b') for byte in cipher_text_3des))


              
    
    # 3DES Decryption Section
    st.title("Triple DES Decryption")
    
    # Prompt user for the three 3DES keys (must be 8 characters each)
    key1_input_dec = st.text_input("Enter the first DES key (8 characters):", key="des_key1_dec")
    key2_input_dec = st.text_input("Enter the second DES key (8 characters):", key="des_key2_dec")
    key3_input_dec = st.text_input("Enter the third DES key (8 characters):", key="des_key3_dec")
    
    # Prompt user for the ciphertext in binary format
    ciphertext_input_3des = st.text_input("Enter the ciphertext (in binary):", key="3des_ciphertext_dec")
    
    # Decryption button
    decrypt_button_3des = st.button("Decrypt (3DES)")
    
    # Run decryption only if all inputs are provided
    if decrypt_button_3des and key1_input_dec and key2_input_dec and key3_input_dec and ciphertext_input_3des:
        # Ensure all keys are valid 8-character DES keys
        if len(key1_input_dec) != 8 or len(key2_input_dec) != 8 or len(key3_input_dec) != 8:
            st.error("Error: Keys must be 8 characters each.")
        else:
            try:
                # Convert the binary ciphertext string to bytes
                ciphertext = int(ciphertext_input_3des, 2).to_bytes(len(ciphertext_input_3des) // 8, byteorder='big')
            except ValueError:
                st.error("Error: Ciphertext must be in binary format.")
                st.stop()
    
            # Check if ciphertext is valid length (multiple of 64 bits = 8 bytes)
            if len(ciphertext) % 8 != 0:
                st.error("Error: Ciphertext must be a multiple of 64 bits.")
                st.stop()
            else:
                # Decrypt the ciphertext using 3DES (Decrypt-Encrypt-Decrypt)
                plain_text_3des = decrypt_3des(
                    ciphertext, 
                    key1_input_dec.encode(), 
                    key2_input_dec.encode(), 
                    key3_input_dec.encode()
                )
    
                # Display the final plaintext
                st.write("Decrypted Plain Text:", plain_text_3des.decode())






elif encryption_scheme == "Blum-Goldwasser":
    # Section title for key generation
    st.title("Blum-Goldwasser Key Generation")

    # Prompt user for bit length to generate two large primes (p and q)
    bit_length = st.number_input("Enter the bit length for primes (e.g., 16, 32, 64, 128, 256):", min_value=16, step=1)

    # Button to generate keys
    generate_keys = st.button("Generate Keys")
    if generate_keys:
        # Generate p, q (both ≡ 3 mod 4), and extended Euclidean values a, b, then compute N = p*q
        p, q, a, b, N = generate_bg_keys(bit_length)

        # Store the generated keys in session state
        st.session_state["public_key"] = N
        st.session_state["private_key_p"] = p
        st.session_state["private_key_q"] = q
        st.session_state["private_key_a"] = a
        st.session_state["private_key_b"] = b
        st.session_state["keys_generated"] = True

        st.success("Keys generated successfully!")

    # Display the generated public and private keys if available
    if st.session_state.get("keys_generated", False):
        st.subheader("Generated Keys")
        st.write("Public Key (N):", st.session_state["public_key"])
        st.write("Private Key (p, q, a, b):",
                 st.session_state["private_key_p"], ",",
                 st.session_state["private_key_q"], ",",
                 st.session_state["private_key_a"], ",",
                 st.session_state["private_key_b"])

    # Section for Blum-Goldwasser encryption
    st.title("Blum-Goldwasser Encryption (Asymmetric)")

    # Prompt user to enter plaintext in binary format (e.g., 010101)
    plaintext_input = st.text_input("Enter the plaintext (binary):")
    public_key = st.session_state.get("public_key", 0)

    # Button to trigger encryption
    encrypt_button = st.button("Encrypt")
    if encrypt_button:
        try:
            # Convert input binary string to list of integers
            plaintext = [int(bit) for bit in plaintext_input.strip()]

            # Encrypt using the Blum-Goldwasser encryption function
            ciphertext, initial_seed = bg_encrypt_message(plaintext, public_key)

            # Format ciphertext for display
            formatted_ciphertext = ", ".join(map(str, ciphertext))
            st.session_state["ciphertext"] = formatted_ciphertext
            st.session_state["initial_seed"] = initial_seed

            st.success("Encryption successful!")
        except Exception as e:
            st.error(f"Encryption failed: {str(e)}")

    # Display the encrypted output if available
    if "ciphertext" in st.session_state:
        st.subheader("Ciphertext")
        st.write("Ciphertext:", st.session_state["ciphertext"])





    

    # Display the initial seed if available
    if "initial_seed" in st.session_state:
        st.subheader("Initial Seed")
        st.write("Initial Seed:", st.session_state["initial_seed"])

    # Section title for decryption
    st.title("Blum-Goldwasser Decryption")

    # User inputs: ciphertext, initial seed, and private/public keys
    ciphertext_input = st.text_input("Enter the ciphertext (comma-separated):")
    initial_seed_str = st.text_input("Enter the initial seed:")
    p_input_str = st.text_input("Enter the value of p:")
    q_input_str = st.text_input("Enter the value of q:")
    a_input_str = st.text_input("Enter the value of a:")
    b_input_str = st.text_input("Enter the value of b:")
    N_input_str = st.text_input("Enter the value of N:")

    # Button to trigger decryption
    decrypt_button = st.button("Decrypt")

    if decrypt_button:
        try:
            # Parse the ciphertext string into a list of integers
            ciphertext = [int(bit) for bit in ciphertext_input.split(",")]

            # Convert all inputs from string to integers, checking for non-empty input
            initial_seed = int(initial_seed_str.strip()) if initial_seed_str.strip() else None
            p_input = int(p_input_str.strip()) if p_input_str.strip() else None
            q_input = int(q_input_str.strip()) if q_input_str.strip() else None
            a_input = int(a_input_str.strip()) if a_input_str.strip() else None
            b_input = int(b_input_str.strip()) if b_input_str.strip() else None
            N_input = int(N_input_str.strip()) if N_input_str.strip() else None

            # Call decryption function with all required parameters
            plaintext = bg_decrypt_message(
                ciphertext,
                initial_seed,
                N_input,
                (p_input, q_input, a_input, b_input)
            )

            # Format the plaintext list for display
            formatted_plaintext = " ".join(map(str, plaintext))
            st.success("Decryption successful!")
            st.write("Plaintext:", formatted_plaintext)

        except Exception as e:
            st.error(f"Decryption failed: {str(e)}")








elif encryption_scheme == "Elgamal and DES (Hybrid)":
    # Section: ElGamal Key Generation
    st.title("ElGamal Key Generation")

    # User input: desired key size for ElGamal keys
    key_size = st.number_input(
        "Enter the key size in bits (preferably 16, 32, 64, 128, 256): ",
        min_value=1,
        value=16,
        key="elgamal_key_size_enc"
    )

    # Button to trigger key generation
    if st.button("Generate Keys"):
        # Generate ElGamal keys (q = prime, g = generator, private/public keys)
        q, g, private_key, public_key = generate_keys_elgamal(key_size)

        # Store the generated keys in session state
        st.session_state['elgamal_q'] = q
        st.session_state['elgamal_g'] = g
        st.session_state['elgamal_private_key'] = private_key
        st.session_state['elgamal_public_key'] = public_key

        st.success("Keys generated successfully!")

    # Display the generated key components
    if 'elgamal_q' in st.session_state:
        st.write("Prime Number (q):", st.session_state['elgamal_q'])
    if 'elgamal_g' in st.session_state:
        st.write("Generator (g):", st.session_state['elgamal_g'])
    if 'elgamal_public_key' in st.session_state:
        st.write("Public Key:", st.session_state['elgamal_public_key'])
    if 'elgamal_private_key' in st.session_state:
        st.write("Private Key (keep this secret!):", st.session_state['elgamal_private_key'])

    # Section: ElGamal Encryption
    st.title("ElGamal Encryption (Asymmetric)")

    # Input for plaintext message to be encrypted using ElGamal
    plaintext = st.text_input("Enter the plaintext message:", key="elgamal_plaintext_enc")

    # Button to trigger encryption
    encrypt_button = st.button("Encrypt Message")

    if encrypt_button and plaintext:
        # Ensure keys are already generated
        if 'elgamal_q' in st.session_state and 'elgamal_g' in st.session_state and 'elgamal_public_key' in st.session_state:
            # Perform encryption and get list of ciphertext tuples
            ciphertext = encrypt_elgamal(
                plaintext,
                st.session_state['elgamal_q'],
                st.session_state['elgamal_g'],
                st.session_state['elgamal_public_key']
            )

            # Display the resulting ciphertext as (c1, c2) pairs
            st.write("Encrypted Message:")
            for pair in ciphertext:
                st.write(f"({pair[0]}, {pair[1]})")
        else:
            st.error("Please generate keys before encryption")




    
    # Section: DES Encryption (Symmetric)
    st.title("DES Encryption (Symmetric)")
    
    # User input: DES key (must be 8 characters = 64 bits)
    key_input = st.text_input("Enter the DES key (8 characters):", key="des_key")
    
    # User input: Plaintext to be encrypted
    # In this hybrid case, the plaintext is the ciphertext output from ElGamal encryption
    plaintext_input = st.text_area(
        "Enter ciphertext from 'Elgamal Encryption' as ordered pairs separated by commas such as (123, 456),(789, 321):",
        height=200,
        key="des_plaintext"
    )
    
    # Button to trigger DES encryption
    encrypt_button = st.button("Encrypt")
    
    # Validate inputs and perform encryption
    if encrypt_button and key_input and plaintext_input:
        # Ensure DES key is exactly 8 characters
        if len(key_input) != 8:
            st.error("Error: Key must be 8 characters.")
        else:
            # Encrypt the plaintext using DES
            cipher_text = encrypt_des(plaintext_input.encode(), key_input.encode())
    
            # Display the encrypted output in binary format
            st.write("Cipher Text in Binary:")
            st.write(''.join(format(byte, '08b') for byte in cipher_text))





    
    
    # Section: DES Decryption
    st.title("DES Decryption")
    
    # User input: DES key (must be exactly 8 characters)
    key_input = st.text_input("Enter the DES key (8 characters):", key="des_key_input")
    
    # User input: Ciphertext in binary format (output from previous DES encryption)
    ciphertext_input = st.text_area(
        "Enter the ciphertext from 'DES Encryption' (in binary):",
        height=200,
        key="des_ciphertext_input"
    )
    
    # Button to trigger decryption
    decrypt_button = st.button("Decrypt")
    
    # Validate inputs and perform decryption
    if decrypt_button and key_input and ciphertext_input:
        # Ensure key is 8 characters
        if len(key_input) != 8:
            st.error("Error: Key must be 8 characters.")
        else:
            try:
                # Convert binary string input into bytes
                ciphertext = int(ciphertext_input, 2).to_bytes(len(ciphertext_input) // 8, byteorder='big')
            except ValueError:
                st.error("Error: Ciphertext must be in binary format.")
                st.stop()
    
            # Ensure ciphertext length is valid for DES (must be multiple of 64 bits = 8 bytes)
            if len(ciphertext) % 8 != 0 or len(key_input) != 8:
                st.error("Error: Ciphertext must be a multiple of 64 bits and the key must be 8 characters.")
                st.stop()
            else:
                # Decrypt using DES
                plain_text = decrypt_des(ciphertext, key_input.encode())
    
                # Remove PKCS5/7-style padding (last byte indicates how many padding bytes were added)
                padding_len = plain_text[-1]
                decrypted_plain_text = plain_text[:-padding_len]
    
                # Display the final plaintext message
                st.write("Decrypted Plain Text:", decrypted_plain_text.decode())



    # ElGamal Decryption Section
    st.title("ElGamal Decryption")

    # Prompt the user to enter the ciphertext
    ciphertext_input = st.text_area("Enter the ciphertext (as ordered pairs separated by commas, e.g., (123,456),(789,012)):", height=200, key="elgamal_ciphertext_dec")

    def parse_ciphertext_input(ciphertext_str):
        try:
            tuple_strs = ciphertext_str.replace(' ', '').split('),(')
            tuple_strs[0] = tuple_strs[0].lstrip('(')
            tuple_strs[-1] = tuple_strs[-1].rstrip(')')
            tuples = [tuple(map(int, t.split(','))) for t in tuple_strs]
            return tuples
        except ValueError:
            return []

    ciphertext = parse_ciphertext_input(ciphertext_input)

   

# Prompt the user to enter the prime number (q) as a string
    q_dec_str = st.text_input("Enter prime number (q) from original key generation:")

# Convert the input string to an integer if it's not empty
    q_dec = int(q_dec_str) if q_dec_str.strip() else None
    
    
# Prompt the user to enter the private key as a string
    private_key_dec_str = st.text_input("Enter your private key from original key generation:")

# Convert the input string to an integer if it's not empty
    private_key_dec = int(private_key_dec_str) if private_key_dec_str.strip() else None
    
    decrypt_button = st.button("Decrypt Ciphertext")

    if decrypt_button and ciphertext and q_dec and private_key_dec:
        try:
            decrypted_message = decrypt_elgamal(ciphertext, q_dec, private_key_dec)
            st.write("Decrypted Message:", decrypted_message)
        except Exception:
            st.error("An error occurred during decryption.")







elif encryption_scheme == "Elgamal and 3DES (Hybrid)":
    # ElGamal Encryption Section
    st.title("ElGamal Key Generation")

    # Get Key Size from User for Encryption
    key_size = st.number_input("Enter the key size in bits (preferably 16, 32, 64, 128, 256): ", min_value=1, value=16, key="elgamal_key_size_enc")

    if st.button("Generate Keys"):
        q, g, private_key, public_key = generate_keys_elgamal(key_size)
        st.session_state['elgamal_q'] = q
        st.session_state['elgamal_g'] = g
        st.session_state['elgamal_private_key'] = private_key
        st.session_state['elgamal_public_key'] = public_key
        st.success("Keys generated successfully!")

    if 'elgamal_q' in st.session_state:
        st.write("Prime Number (q):", st.session_state['elgamal_q'])
    if 'elgamal_g' in st.session_state:
        st.write("Generator (g):", st.session_state['elgamal_g'])
    if 'elgamal_public_key' in st.session_state:
        st.write("Public Key:", st.session_state['elgamal_public_key'])
    if 'elgamal_private_key' in st.session_state:
        st.write("Private Key (keep this secret!):", st.session_state['elgamal_private_key'])

    st.title("ElGamal Encryption (Asymmetric)")

    plaintext = st.text_input("Enter the plaintext message:", key="elgamal_plaintext_enc")
    encrypt_button = st.button("Encrypt Message")

    if encrypt_button and plaintext:
        if 'elgamal_q' in st.session_state and 'elgamal_g' in st.session_state and 'elgamal_public_key' in st.session_state:
            ciphertext = encrypt_elgamal(plaintext, st.session_state['elgamal_q'], st.session_state['elgamal_g'], st.session_state['elgamal_public_key'])
            st.write("Encrypted Message:")
            for pair in ciphertext:
                st.write(f"({pair[0]}, {pair[1]})")
        else:
            st.error("Please generate keys before encryption")



    
    st.title("3DES Encryption (Symmetric)")

    # Key input
    key1_input = st.text_input("Enter the first DES key (8 characters):", key="des_key1_enc")
    key2_input = st.text_input("Enter the second DES key (8 characters):", key="des_key2_enc")
    key3_input = st.text_input("Enter the third DES key (8 characters):", key="des_key3_enc")

    # Plaintext input
    plaintext_input_3des = st.text_area("Enter ciphertext from 'Elgamal Encryption' as ordered pairs separated by commas such as (123, 456),(789, 321):", height=200,key="3des_plaintext_enc")

    # Encryption button
    encrypt_button_3des = st.button("Encrypt (3DES)")

    if encrypt_button_3des and key1_input and key2_input and key3_input and plaintext_input_3des:
        if len(key1_input) != 8 or len(key2_input) != 8 or len(key3_input) != 8:
            st.error("Error: Keys must be 64 bits each.")
        else:
            # Convert keys and plaintext to bit arrays
            # key1_des = key1_input.encode()
            # key2_des = key2_input.encode()
            # key3_des = key3_input.encode()
            # plaintext_3des = pad_message(plaintext_input_3des.encode())

            # Encrypt the plaintext using 3DES
            cipher_text_3des = encrypt_3des(plaintext_input_3des.encode(), key1_input.encode(), key2_input.encode(), key3_input.encode())

            # Display ciphertext
            st.write("Cipher Text for 3DES (binary):")
            
            st.write(''.join(format(byte, '08b') for byte in cipher_text_3des))

 




    st.title("3DES Decryption")
    # Key input
    key1_input_dec = st.text_input("Enter the first DES key (8 characters):", key="des_key1_dec")
    key2_input_dec = st.text_input("Enter the second DES key (8 characters):", key="des_key2_dec")
    key3_input_dec = st.text_input("Enter the third DES key (8 characters):", key="des_key3_dec")

    # Ciphertext input
    ciphertext_input_3des = st.text_area("Enter the ciphertext (in binary):", height=200,key="3des_ciphertext_dec")

    # Decryption button
    decrypt_button_3des = st.button("Decrypt (3DES)")

    if decrypt_button_3des and key1_input_dec and key2_input_dec and key3_input_dec and ciphertext_input_3des:
        if len(key1_input_dec) != 8 or len(key2_input_dec) != 8 or len(key3_input_dec) != 8:
            st.error("Error: Keys must be 8 characters each.")
        else:
            try:
                ciphertext = int(ciphertext_input_3des, 2).to_bytes(len(ciphertext_input_3des) // 8, byteorder='big')
            except ValueError:
                st.error("Error: Ciphertext must be in binary format.")
                st.stop()
            if len(ciphertext) % 8 != 0 or len(key1_input_dec) != 8 or len(key2_input_dec) != 8 or len(key3_input_dec) != 8:
                st.error("Error: Ciphertext must be a multiple of 64 bits and the key must be 8 characters.")
                st.stop()                
            else:
            # Decrypt the ciphertext using 3DES
            # Decrypt the ciphertext using 3DES
                plain_text_3des = decrypt_3des(ciphertext, key1_input_dec.encode(), key2_input_dec.encode(), key3_input_dec.encode())
            
            # Extract padding length
            #     padding_len = plain_text_3des[-1]
            
            # # Remove padding
            #     decrypted_plain_text_3des = plain_text_3des[:-padding_len]
            
                st.write("Decrypted Plain Text:", plain_text_3des.decode())





    # ElGamal Decryption Section
    st.title("ElGamal Decryption")

    # Prompt the user to enter the ciphertext
    ciphertext_input = st.text_area("Enter the ciphertext (as ordered pairs separated by commas, e.g., (123,456),(789,012)):", height=200, key="elgamal_ciphertext_dec")

    def parse_ciphertext_input(ciphertext_str):
        try:
            tuple_strs = ciphertext_str.replace(' ', '').split('),(')
            tuple_strs[0] = tuple_strs[0].lstrip('(')
            tuple_strs[-1] = tuple_strs[-1].rstrip(')')
            tuples = [tuple(map(int, t.split(','))) for t in tuple_strs]
            return tuples
        except ValueError:
            return []

    ciphertext = parse_ciphertext_input(ciphertext_input)

   

# Prompt the user to enter the prime number (q) as a string
    q_dec_str = st.text_input("Enter Prime number (q) from original key generation:")

# Convert the input string to an integer if it's not empty
    q_dec = int(q_dec_str) if q_dec_str.strip() else None
    
    
# Prompt the user to enter the private key as a string
    private_key_dec_str = st.text_input("Enter your Private Key from original key generation:")

# Convert the input string to an integer if it's not empty
    private_key_dec = int(private_key_dec_str) if private_key_dec_str.strip() else None
    
    decrypt_button = st.button("Decrypt Ciphertext")

    if decrypt_button and ciphertext and q_dec and private_key_dec:
        try:
            decrypted_message = decrypt_elgamal(ciphertext, q_dec, private_key_dec)
            st.write("Decrypted Message:", decrypted_message)
        except Exception:
            st.error("An error occurred during decryption.")
   
    
     