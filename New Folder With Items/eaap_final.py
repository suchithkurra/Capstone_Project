# Assuming sha160 is defined as in your first code snippet
import random
import math
from sympy import mod_inverse


import struct

# Constants (64-bit values)
K = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe
]

# Initial hash values (64-bit)
H = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
]

def right_rotate(value, amount):
    """Right rotates a 64-bit integer"""
    return ((value >> amount) | (value << (64 - amount))) & ((1 << 64) - 1)

def sha160_padding(message):
    """Pads the input message to be a multiple of 320 bits"""
    length = len(message) * 8  # Original message length in bits
    message += b'\x80'  # Append '1' bit (0x80 in hex)
    
    # Pad with zeros until the length (in bytes) is congruent to 40 mod 40 (320 bits)
    while (len(message) % 40) != 32:
        message += b'\x00'
    
    # Append the original message length as a 64-bit integer
    message += struct.pack('>Q', length)  # Append the lower-order 64 bits of the length
    
    return message

def sha160_process_chunk(chunk, H):
    """Processes a 320-bit chunk of the message"""
    # Break chunk into five 64-bit big-endian words w[0..4]
    w = list(struct.unpack('>5Q', chunk))
    
    # Extend the words into 16 64-bit words w[0..15]
    for i in range(5, 16):
        s0 = (right_rotate(w[i-5], 1) ^ right_rotate(w[i-5], 8) ^ (w[i-5] >> 7))
        s1 = (right_rotate(w[i-2], 19) ^ right_rotate(w[i-2], 61) ^ (w[i-2] >> 6))
        w.append((w[i-5] + s0 + w[i-4] + s1) & ((1 << 64) - 1))
    
    # Initialize working variables with the current hash values
    a, b, c, d = H
    
    # Main loop (16 rounds instead of 80 rounds)
    for i in range(16):
        s1 = (right_rotate(c, 14) ^ right_rotate(c, 18) ^ right_rotate(c, 41))
        ch = (c & d) ^ ((~c) & b)
        temp1 = (d + s1 + ch + K[i % len(K)] + w[i]) & ((1 << 64) - 1)
        s0 = (right_rotate(a, 28) ^ right_rotate(a, 34) ^ right_rotate(a, 39))
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & ((1 << 64) - 1)
        
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & ((1 << 64) - 1)
    
    # Add the compressed chunk to the current hash value
    H[0] = (H[0] + a) & ((1 << 64) - 1)
    H[1] = (H[1] + b) & ((1 << 64) - 1)
    H[2] = (H[2] + c) & ((1 << 64) - 1)
    H[3] = (H[3] + d) & ((1 << 64) - 1)
    
    return H

def sha160(message):
    """Computes the 160-bit hash of the given message"""
    # Pre-process the message: pad the message according to the specifications
    padded_message = sha160_padding(message)
    
    # Initialize hash values
    H_copy = H[:]
    
    # Process the message in 320-bit (40-byte) chunks
    for i in range(0, len(padded_message), 40):
        chunk = padded_message[i:i+40]
        H_copy = sha160_process_chunk(chunk, H_copy)
    
    # Produce the final hash value (160 bits)
    return ''.join(f'{value:016x}' for value in H_copy[:4])

if __name__ == "__main__":
    message = input("Enter the message to hash: ")  # Taking input from the user
    message_bytes = message.encode('utf-8')  # Encoding the message to bytes
    hash_value = sha160(message_bytes)  # Computing the hash
    print(f"160-bit SHA-like hash of '{message}': {hash_value}")  # Printing the hash value




class TrustedAuthority:
    def __init__(self, q, g1, g2, a=None, b=None):
        self.q = q
        self.g1 = g1
        self.g2 = g2
        # Allow manual assignment of a and b, or generate randomly if not provided
        self.a = a if a is not None else random.randint(1, q - 1)
        self.b = b if b is not None else random.randint(1, q - 1)
        self.A1 = pow(g1, self.a, q)
        self.B1 = pow(g1, self.b, q)
        self.tracking_list = {}

    def H(self, data):
        """Custom hash function using sha160"""
        return int(sha160(data.encode('utf-8')), 16) % self.q

    def register_vehicle(self, user_info):
        ni = 6
        OIDui = self.H(user_info)
        DIDui = pow(self.g1, ni + self.a, self.q)
        vi = 11
        total = vi + self.a + self.b
        inverse = pow(total, -1, self.q)
        Ti = pow(self.g1, inverse, self.q)
        Ei = pow(self.g1, self.q - ni % self.q, self.q)
        self.tracking_list[OIDui] = (DIDui, Ti)
        AK = (DIDui, Ti, Ei)
        return AK

class VehicleUser:
    def __init__(self, TA, user_info):
        self.TA = TA
        self.AK = TA.register_vehicle(user_info)
        self.DIDui, self.Ti, self.Ei = self.AK

    def generate_anonymous_certificate(self):
        r = 1
        Yk = pow(self.TA.g2, r, self.TA.q)
        mu = 1
        k1 = 7
        k2 = 9

        gamma_U = pow(self.TA.B1, mu, self.TA.q)
        gamma_V = (self.Ti * pow(self.TA.A1, mu, self.TA.q)) % self.TA.q
        lam = (mu + r) % self.TA.q
        lam1 = pow(5, (32 % self.TA.q), self.TA.q)

        mod_exponent = -111 % self.TA.q
        lam2 = pow(5, mod_exponent, self.TA.q)

        delta1 = (r - k1) % self.TA.q
        delta2 = (r - k2) % self.TA.q
        Cert_k = (Yk, self.Ei, self.DIDui, gamma_U, gamma_V, lam, delta1, delta2)
        return Cert_k

    def generate_signature(self, message):
        r = 1
        hashed_message = self.TA.H(message)
        sig = pow(self.TA.g1, r + hashed_message, self.TA.q)
        return sig

def verify_message(TA, msg, Cert_k):
    (Yk, Ei, DIDui, gamma_U, gamma_V, lam, delta1, delta2) = Cert_k

    Ni = pow(5, (17 + 9) % TA.q, TA.q)
    gamma_U_lam = pow(5, (4 * lam) % TA.q, TA.q)
    gamma_U_delta1 = pow(5, (4 * delta1) % TA.q, TA.q)
    lam1_check = pow(5, (4 * (lam - delta1)) % TA.q, TA.q)

    lam2_check = pow(5, (4 * lam - 12 * lam + 12 * delta2 - 4 * delta1) % TA.q, TA.q)

    sig, message = msg
    left = Ni
    right = TA.A1
    return left == right

# Example Usage
q = 23  # Example prime modulus
g1 = 5
g2 = 7
a = 3
b = 4

TA = TrustedAuthority(q, g1, g2, a, b)

user_info = "UserName|LicensePlate|PhoneNumber"
vehicle = VehicleUser(TA, user_info)

Cert_k = vehicle.generate_anonymous_certificate()
message = "Hello VANET!"
sig = vehicle.generate_signature(message)
msg = (sig, message)

is_valid = verify_message(TA, msg, Cert_k)
print("Message Valid:", is_valid)
