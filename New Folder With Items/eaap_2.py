import random
from hashlib import sha256
from sympy import mod_inverse
import math

# Bilinear parameters and setup
class TrustedAuthority:
    def __init__(self, q, g1, g2, a=None, b=None):
        self.q = q
        self.g1 = g1
        self.g2 = g2
        self.a = a if a is not None else random.randint(1, q - 1)
        self.b = b if b is not None else random.randint(1, q - 1)
        self.A1 = pow(g1, self.a, self.q)
        self.B1 = pow(g1, self.b, self.q)
        # Cryptographic hash function
        self.H = lambda x: int(sha256(str(x).encode()).hexdigest(), 16) % self.q
        self.tracking_list = {}

    def register_vehicle(self, user_info):
        ni = random.randint(1, self.q - 1)  # Random value for ni
        OIDui = self.H(user_info)  # Original Identity
        DIDui = pow(self.g1, ni + self.a, self.q)  # Derived Identity
        vi = random.randint(1, self.q - 1)  # Random value for vi
        Ti = pow(self.g1, mod_inverse(self.a + self.b + vi, self.q), self.q)  # Computed Ti
        Ei = pow(self.g1, (self.q - ni) % self.q, self.q)  # Computed Ei
        self.tracking_list[OIDui] = (DIDui, Ti)
        return DIDui, Ti, Ei

class VehicleUser:
    def __init__(self, TA, user_info):
        self.TA = TA
        self.AK = TA.register_vehicle(user_info)
        self.DIDui, self.Ti, self.Ei = self.AK

    def generate_anonymous_certificate(self):
        r = random.randint(1, self.TA.q - 1)  # Random r
        mu = random.randint(1, self.TA.q - 1)  # Random mu
        k1 = random.randint(1, self.TA.q - 1)  # Random k1
        k2 = random.randint(1, self.TA.q - 1)  # Random k2

        # Compute gamma values
        gamma_U = pow(self.TA.B1, mu, self.TA.q)
        gamma_V = (self.Ti * pow(self.TA.A1, mu, self.TA.q)) % self.TA.q

        # Compute lambda values
        lam = (mu + r) % self.TA.q
        lam1 = pow(gamma_U, mu + k1, self.TA.q)
        lam2 = pow(gamma_U, (mu + k1 - (mu + k2)) % self.TA.q, self.TA.q)

        # Compute challenge c
        c = self.TA.H(f"{self.DIDui}{self.TA.A1}{self.TA.B1}{self.Ei}{gamma_U}{gamma_V}{r}{lam1}{lam2}")
        delta1 = (r - k1) % self.TA.q
        delta2 = (r - k2) % self.TA.q

        return (pow(self.TA.g2, r, self.TA.q), self.Ei, self.DIDui, gamma_U, gamma_V, c, lam, delta1, delta2)

    def generate_signature(self, message):
        r = random.randint(1, self.TA.q - 1)  # Random r for signature
        sig = pow(self.TA.g1, r + self.TA.H(message), self.TA.q)
        return sig

def verify_message(TA, msg, Cert_k):
    (Yk, Ei, DIDui, gamma_U, gamma_V, c, lam, delta1, delta2) = Cert_k

    # Compute intermediate values
    Ni = Ei * DIDui % TA.q

    # Breaking down lam1_check calculation
    gamma_U_lam = pow(gamma_U, lam, TA.q)
    gamma_U_delta1 = pow(gamma_U, delta1, TA.q)
    lam1_check = (gamma_U_lam * mod_inverse(gamma_U_delta1, TA.q)) % TA.q

    # Breaking down lam2_check calculation
    gamma_V_lam = pow(gamma_V, lam, TA.q)
    gamma_V_delta2 = pow(gamma_V, delta2, TA.q)
    lam2_check = (gamma_U_lam * gamma_V_delta2) * mod_inverse(gamma_U_delta1 * gamma_V_lam, TA.q) % TA.q

    # Verify challenge
    c_check = TA.H(f"{DIDui}{Ni}{TA.B1}{Ei}{gamma_U}{gamma_V}{Yk}{lam1_check}{lam2_check}")
    if c != c_check:
        return False

    # Verify signature
    sig, message = msg
    left = pow(sig, Yk * pow(TA.g2, TA.H(message), TA.q), TA.q)
    right = lam2_check
    return left == right


# Example Usage
q = 23  # Example prime modulus
g1 = 5
g2 = 7
a = 7  # Manually set master secret key a
b = 7  # Manually set master secret key b

# Initialize Trusted Authority with manually set a and b
TA = TrustedAuthority(q, g1, g2, a, b)

# Print values to verify
print(f"a: {TA.a}, b: {TA.b}")
print(f"A1: {TA.A1}, B1: {TA.B1}")

user_info = "UserName|LicensePlate|PhoneNumber"
vehicle = VehicleUser(TA, user_info)

Cert_k = vehicle.generate_anonymous_certificate()
message = "Hello VANET!"
sig = vehicle.generate_signature(message)
msg = (sig, message)

# Verify the message
is_valid = verify_message(TA, msg, Cert_k)
print("Message Valid:", is_valid)
