from cryptography.hazmat.primitives.asymmetric import rsa

AUTH_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)