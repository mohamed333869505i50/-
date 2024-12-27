import math

# Function to compute the greatest common divisor
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Function to compute modular inverse
def mod_inverse(e, phi):
    for d in range(1, phi):
        if (e * d) % phi == 1:
            return d
    return None

# RSA Key Generation
def generate_keys(p, q, e):
    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime with phi")
    d = mod_inverse(e, phi)
    if d is None:
        raise ValueError("Modular inverse of e does not exist")
    return (n, e), (n, d)

# RSA Encryption
def encrypt(message, public_key):
    n, e = public_key
    return pow(message, e, n)

# RSA Decryption
def decrypt(ciphertext, private_key):
    n, d = private_key
    return pow(ciphertext, d, n)

# Main function to get input and execute RSA
if __name__ == "__main__":
    # Get values from the user
    p = int(input("Enter prime p: "))
    q = int(input("Enter prime q: "))
    e = int(input("Enter e: "))
    message = int(input("Enter message (integer): "))

    try:
        # Key generation
        public_key, private_key = generate_keys(p, q, e)
        print(f"Public Key: {public_key}")
        print(f"Private Key: {private_key}")

        # Encryption
        ciphertext = encrypt(message, public_key)
        print(f"Ciphertext: {ciphertext}")

        # Decryption
        decrypted_message = decrypt(ciphertext, private_key)
        print(f"Decrypted Message: {decrypted_message}")
    
    except ValueError as ve:
        print(f"Error: {ve}")