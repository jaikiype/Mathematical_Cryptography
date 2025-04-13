import streamlit as st
from Crypto.Util import number

# --- Helper Functions ---
def generate_large_primes(bits=1024):
    p = number.getPrime(bits)
    q = number.getPrime(bits)
    while abs(p - q) < 2**(bits - 100):  # Avoid close primes
        q = number.getPrime(bits)
    return p, q

def generate_keys(bits=1024):
    p, q = generate_large_primes(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi)
    return (n, e), (n, d), p, q

def text_to_ascii_integer(text):
    return int(''.join(f"{ord(c):03}" for c in text))

def int_to_text_ascii(value):
    s = str(value)
    if len(s) % 3 != 0:
        s = s.zfill(len(s) + 3 - len(s) % 3)
    return ''.join(chr(int(s[i:i+3])) for i in range(0, len(s), 3))

def rsa_encrypt(m, e, n):
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

# --- Streamlit App ---
st.set_page_config(page_title="RSA Encryption App", layout="centered")
st.title("🔐 RSA Encryption & Decryption")

# --- Session Keys ---
if "public_key" not in st.session_state:
    st.session_state.public_key, st.session_state.private_key, st.session_state.p, st.session_state.q = generate_keys()

# --- Key Generation Section ---
st.subheader("🔑 Phase 1: Key Generation")

if st.button("Generate New RSA Keys"):
    st.session_state.public_key, st.session_state.private_key, st.session_state.p, st.session_state.q = generate_keys()
    st.success("New keys generated!")

n, e = st.session_state.public_key
_, d = st.session_state.private_key

# Public + Private Keys (Outside)
with st.expander("📖 View Generated Keys"):
    st.markdown("### 🔓 Public Key")

    pub_n = st.text_input("Modulus (n)", value=str(n), key="pub_n")
    pub_e = st.text_input("Public Exponent (e)", value=str(e), key="pub_e")

    st.markdown("### 🔐 Private Key")
    priv_d = st.text_input("Private Exponent (d)", value=str(d), key="priv_d")

# Prime Numbers (Advanced - Separate Expander)
with st.expander("🔬 Advanced (Primes p & q)"):
    priv_p = st.text_input("Prime p", value=str(st.session_state.p), key="priv_p")
    priv_q = st.text_input("Prime q", value=str(st.session_state.q), key="priv_q")

# --- Encryption Section ---
st.subheader("✉️ Phase 2: Encryption")

plaintext = st.text_area("Enter message to encrypt:")
enc_n = st.text_input("Public Key (n)", value=str(n), key="enc_n")
enc_e = st.text_input("Public Exponent (e)", value=str(e), key="enc_e")

if st.button("Encrypt"):
    if plaintext and enc_n and enc_e:
        try:
            enc_n = int(enc_n)
            enc_e = int(enc_e)
            m = text_to_ascii_integer(plaintext)
            c = rsa_encrypt(m, enc_e, enc_n)
            st.session_state.ciphertext = c
            st.success("Encryption successful!")
            st.code(f"{c}", language='python')
        except ValueError:
            st.error("Invalid public key values. Make sure n and e are integers.")
    else:
        st.warning("Please fill in the plaintext and both public key fields.")

# --- Decryption Section ---
st.subheader("🔓 Phase 3: Decryption")

ciphertext_input = st.text_area("Enter ciphertext to decrypt:")
dec_n = st.text_input("Private Key (n)", value=str(n), key="dec_n")
dec_d = st.text_input("Private Exponent (d)", value=str(d), key="dec_d")

if st.button("Decrypt"):
    if ciphertext_input and dec_n and dec_d:
        try:
            dec_n = int(dec_n)
            dec_d = int(dec_d)
            c = int(ciphertext_input)
            m = rsa_decrypt(c, dec_d, dec_n)
            decrypted_text = int_to_text_ascii(m)
            st.success("Decryption successful!")
            st.code(f"{decrypted_text}", language='python')
        except ValueError:
            st.error("Make sure ciphertext, n, and d are all valid integers.")
    else:
        st.warning("Please enter all fields to decrypt the message.")

st.caption("Developed by Jaik Iype and Group 5  – Cryptographic Mathematics Project")
