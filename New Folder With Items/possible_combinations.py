class EllipticCurve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    def point_addition(self, P, Q):
        if P == Q:
            # Point doubling
            lmbda = (3 * P[0]**2 + self.a) * pow(2 * P[1], -1, self.p) % self.p
        else:
            # General point addition
            lmbda = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, self.p) % self.p

        x_r = (lmbda**2 - P[0] - Q[0]) % self.p
        y_r = (lmbda * (P[0] - x_r) - P[1]) % self.p
        return (x_r, y_r)

    def scalar_multiplication(self, k, P):
        R = None
        N = P

        while k:
            if k % 2 == 1:
                if R is None:
                    R = N
                else:
                    R = self.point_addition(R, N)
            N = self.point_addition(N, N)
            k //= 2

        return R

    def find_all_points(self):
        points = []
        for x in range(self.p):
            rhs = (x**3 + self.a * x + self.b) % self.p  # Compute RHS of the equation

            # Iterate over all y values and check if y^2 mod p = rhs
            for y in range(self.p):
                if (y**2) % self.p == rhs:
                    points.append((x, y))  # Add valid point to the list
        return points

# Get input values from the user
a = int(input("Enter coefficient a: "))
b = int(input("Enter coefficient b: "))
p = int(input("Enter prime modulus p: "))

# Create elliptic curve object
curve = EllipticCurve(a, b, p)

# Find all points on the curve
points = curve.find_all_points()
print(f"All points on the elliptic curve: {points}")


xP = int(input("Enter x-coordinate of point P: "))
yP = int(input("Enter y-coordinate of point P: "))
xQ = int(input("Enter x-coordinate of point Q: "))
yQ = int(input("Enter y-coordinate of point Q: "))
k = int(input("Enter scalar k for multiplication: "))



# Perform point addition
P = (xP, yP)
Q = (xQ, yQ)
R = curve.point_addition(P, Q)
print(f"Point addition result (-R): {R}")

# Perform scalar multiplication
S = curve.scalar_multiplication(k, P)
print(f"Scalar multiplication result: {S}")