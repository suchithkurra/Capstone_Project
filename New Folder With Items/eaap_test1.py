import random
from hashlib import sha256

# Bilinear parameters and setup
class TrustedAuthority:
    def __init__(self, q, g1, g2):
        self.q = q
        self.g1 = g1
        self.g2 = g2
        self.a = random.randint(1, q - 1)  # Master secret keys
        self.b = random.randint(1, q - 1)
        self.A1 = pow(g1, self.a, q)
        self.B1 = pow(g1, self.b, q)
        self.H = lambda x: int(sha256(x.encode()).hexdigest(), 16) % q
        self.tracking_list = {}

    def register_vehicle(self, user_info):
        # Original identity and dummy identity generation
        ni = random.randint(1, self.q - 1)
        OIDui = self.H(user_info)
        DIDui = pow(self.g1, ni + self.a, self.q)
        vi = random.randint(1, self.q - 1)
        Ti = pow(self.g1, vi + self.a + self.b, self.q)
        Ei = pow(self.g1, -ni, self.q)
        self.tracking_list[OIDui] = (DIDui, Ti)
        AK = (DIDui, Ti, Ei)
        return AK

class VehicleUser:
    def __init__(self, TA, user_info):
        self.TA = TA
        self.AK = TA.register_vehicle(user_info)
        self.DIDui, self.Ti, self.Ei = self.AK

    def generate_anonymous_certificate(self):
        r = random.randint(1, self.TA.q - 1)
        Yk = pow(self.TA.g2, r, self.TA.q)
        mu = random.randint(1, self.TA.q - 1)
        k1 = random.randint(1, self.TA.q - 1)
        k2 = random.randint(1, self.TA.q - 1)

        # Compute gamma and lambda values
        gamma_U = pow(self.TA.B1, mu, self.TA.q)
        gamma_V = (self.Ti * pow(self.TA.A1, mu, self.TA.q)) % self.TA.q
        lam = (mu + r) % self.TA.q
        lam1 = (gamma_U * pow(gamma_U, k1, self.TA.q)) % self.TA.q
        lam2 = (pow(gamma_U, k1, self.TA.q) * pow(gamma_V, k2, self.TA.q)) % self.TA.q

        # Compute challenge and responses
        c = self.TA.H(f"{self.DIDui}{self.TA.A1}{self.TA.B1}{self.Ei}{gamma_U}{gamma_V}{Yk}{lam1}{lam2}")
        delta1 = (r - k1) % self.TA.q
        delta2 = (r - k2) % self.TA.q

        Cert_k = (Yk, self.Ei, self.DIDui, gamma_U, gamma_V, c, lam, delta1, delta2)
        return Cert_k

    def generate_signature(self, message):
        r = random.randint(1, self.TA.q - 1)
        sig = pow(self.TA.g1, r + self.TA.H(message), self.TA.q)
        return sig

def verify_message(TA, msg, Cert_k):
    (Yk, Ei, DIDui, gamma_U, gamma_V, c, lam, delta1, delta2) = Cert_k

    # Compute intermediate values
    Ni = (Ei * DIDui) % TA.q
    lam1_check = (pow(gamma_U, lam, TA.q) * pow(gamma_U, delta1, TA.q)) % TA.q
    lam2_check = (pow(gamma_U, lam, TA.q) * pow(gamma_V, delta2, TA.q)) % TA.q

    # Verify challenge
    c_check = TA.H(f"{DIDui}{Ni}{TA.B1}{Ei}{gamma_U}{gamma_V}{Yk}{lam1_check}{lam2_check}")
    if c != c_check:
        return False

    # Verify signature
    sig, message = msg
    left = pow(sig, Yk * pow(TA.g2, TA.H(message), TA.q), TA.q)
    right = pow(TA.g1, TA.g2, TA.q)
    return left == right

# Example Usage
q = 1019  # Example prime modulus
g1 = 2
g2 = 5
TA = TrustedAuthority(q, g1, g2)

user_info = "UserName|LicensePlate|PhoneNumber"
vehicle = VehicleUser(TA, user_info)

Cert_k = vehicle.generate_anonymous_certificate()
message = "Hello VANET!"
sig = vehicle.generate_signature(message)
msg = (sig, message)

# Verify the message
is_valid = verify_message(TA, msg, Cert_k)
print("Message Valid:", is_valid)
