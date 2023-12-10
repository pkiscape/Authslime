#=========================================================
# Authslime
# X50slime 
# X509 certificate requester/issuer and keypair generator
#=========================================================



import getpass 
import os
import string
import binascii
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)

def wrapkeypair(privkey_pem,slimeid):

	'''
	
	Master Keypair 
	      |
		  | (Encrypts)
		  V
	    SymKey	  
		  |
		  | (Encrypts)
	      V
	  PrivateKey(Assocaited with SlimeCert)

	1) Create Symmetric Key, IV
	2) Encrypt Slime Private Key with Symmetric Key = wrappedprivatekey
	3) Encrypt Symmetric Key with Public Key = wrappedsymkey
	4) Store wrappedsymkey and wrappedprivatekey (Also aad/tag/iv)

	To decrypt, use masterkeypair to decrypt symmetric key. Use symmetric key to decrypt wrappedprivatekey

	'''
	encrypted_details = []

	public_key_path = "keys/publickey.pem"

	with open(public_key_path, "rb") as publickeyfile:
		public_key = serialization.load_pem_public_key(publickeyfile.read(),backend=default_backend())
	
	aad = str(slimeid).encode()
	b_key = os.urandom(32)
	iv = os.urandom(12)

	#Symmetric Enc
	b_privkey_pem = str(privkey_pem).encode()
	encryptor = Cipher(algorithms.AES(b_key),modes.GCM(iv),).encryptor()
	encryptor.authenticate_additional_data(aad)
	wrappedprivatekey = encryptor.update(b_privkey_pem) + encryptor.finalize()

	#Asymmetric Enc
	key = binascii.hexlify(b_key).decode('utf-8')
	wrappedsymkey = public_key.encrypt(
	        key.encode('utf-8'),
	        padding.OAEP(
	            mgf=padding.MGF1(algorithm=hashes.SHA256()),
	            algorithm=hashes.SHA256(),
	            label=None
	        )
	    )

	encrypted_details.append(wrappedsymkey)
	encrypted_details.append(iv)
	encrypted_details.append(aad)
	encrypted_details.append(encryptor.tag)
	encrypted_details.append(wrappedprivatekey)

	return encrypted_details

def decrypt_test(encrypted_details):

	wrappedsymkey = encrypted_details[0]
	iv = encrypted_details[1]
	aad = encrypted_details[2]
	tag = encrypted_details[3]
	wrappedprivatekey = encrypted_details[4]

	priv_key_path = "keys/privatekey.pem"
	with open(priv_key_path, "rb") as private_key_file:
		privatekey = private_key_file.read()

	privatekey = serialization.load_pem_private_key(privatekey, password=None, backend=default_backend())

	p_key = privatekey.decrypt(
        wrappedsymkey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))

	p_key = p_key.decode()
	p_key = binascii.unhexlify(p_key)
	decryptor = Cipher(algorithms.AES(p_key),modes.GCM(iv, tag),).decryptor()
	decryptor.authenticate_additional_data(aad)
	decrypted = decryptor.update(wrappedprivatekey) + decryptor.finalize()
	decrypted = decrypted.decode()
	print("Decrypted message is " + decrypted)


def createkeypair(slimeid):

	'''
	1) Generates an ECC keypair (SECP256R1)
	2) Passes wrapkeypair() to encrypt privatekey
	3) Encrypts PrivateKey with password
	4) Pulls publickey from keypair
	5) Puts data into list, and returns it
		[plaintext privatekey,  encrypted privatekey, publickey, salt, hashed password]
	'''

	privkey = ec.generate_private_key(ec.SECP256R1())

	privkey_pem = privkey.private_bytes(
	    encoding=serialization.Encoding.PEM,
	    format=serialization.PrivateFormat.PKCS8,
	    encryption_algorithm=serialization.NoEncryption()
	)
	
	encrypted_details = wrapkeypair(privkey_pem,slimeid)
	
	#decrypt_test(encrypted_details)

	publickey = privkey.public_key()

	#Serialize public key in PEM and DER
	publickey_pem = publickey.public_bytes(encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo)	

	publickey_der = publickey.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
	)

	hash_algo = hashes.SHA256() 
	hashed_public_key = hashes.Hash(hash_algo, default_backend())
	hashed_public_key.update(publickey_der)
	publickey_digest = hashed_public_key.finalize()
	publickey_digest = binascii.hexlify(publickey_digest).decode('utf-8')

	privkey_list = [privkey,publickey_pem]

	#I have to add publickey_digest to the end because I already had dependancies on the order
	keys_table_list = privkey_list + encrypted_details
	keys_table_list.append(publickey_digest)
	
	return keys_table_list
	
def createslimecsr(privkey,commonname,uid):

	# Subject Builder
	subject_attributes = []
	subject_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, commonname))
	subject_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, "Slimeville"))
	subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Pkiscape"))
	subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authslime"))
	subject_attributes.append(x509.NameAttribute(NameOID.USER_ID, str(uid)))

	subject = x509.Name(subject_attributes)

	# Build the CSR defining Subject
	csr = x509.CertificateSigningRequestBuilder().subject_name(subject)

	# Sign CSR with PrivateKey
	csr = csr.sign(privkey, hashes.SHA256())

	# Serialize CSR to PEM format			
	csr_pem = csr.public_bytes(encoding=serialization.Encoding.PEM)

	# Convert bytes to a string
	csr_pem_str = csr_pem.decode()

	return csr

def issueslimecert(csr,uid):
	'''
	Slime Certificate:

	Subject: 
		CommonName: SlimeName_Color_Version
		Locality: Slimeville
		Organization Name: Pkiscape
		Organization Unit: Authslime
		UserID: Slime UID

	Extensions:
		Basic Constraints: CA:False, critical 
		KeyUsage: digitalSignature , nonRepudiation, critical
	'''

	# Define CA Private Key and Certificate
	ca_private_key = "ca/private/ca.key" #This is a testing Root CA *Not for Production*
	ca_certificate = "ca/certs/ca.pem"

	# Load Private key and Certificate

	#Private Key
	with open(ca_private_key, "rb") as private_key_file:
		loaded_privatekey = private_key_file.read()

	try:
		loaded_privatekey = serialization.load_pem_private_key(loaded_privatekey, password=None, backend=default_backend())

	except:
		print("Is your private key encrypted? If so:")
		password = getpass.getpass("Enter the password for the private key: ")
		try:
			loaded_privatekey = serialization.load_pem_private_key(loaded_privatekey,password=password.encode(),backend=default_backend())
			print("Encrypted private key loaded")

		except ValueError:
			print("Incorrect password or unable to load the private key.")
			

	#Certificate
	try:
		with open(ca_certificate, "rb") as cert_file:
			loaded_ca_certificate = x509.load_pem_x509_certificate(cert_file.read(),default_backend())

	except ValueError:
		with open(ca_certificate, "rb") as cert_file:
			loaded_ca_certificate = x509.load_der_x509_certificate(cert_file.read(),default_backend())

	# Define validity period
	validity_period = timedelta(days=3*365)  
	not_valid_before = datetime.utcnow()
	not_valid_after = not_valid_before + validity_period

	# Define Extensions
	basic_constraints = x509.BasicConstraints(ca=False, path_length=None)

	key_usage = x509.KeyUsage(
			digital_signature=True,
			key_encipherment=False,
			content_commitment=True,
			data_encipherment=False,
			key_agreement=False,
			key_cert_sign=False,
			crl_sign=False,
			encipher_only=False,
			decipher_only=False
			)

	#Sign CSR
	slime_certificate_obj = (
    x509.CertificateBuilder()
    .subject_name(csr.subject)
    .issuer_name(loaded_ca_certificate.issuer)
    .public_key(csr.public_key())
    .not_valid_before(not_valid_before)
    .not_valid_after(not_valid_after)
    .serial_number(x509.random_serial_number())
    .add_extension(basic_constraints, critical=True)
    .add_extension(key_usage, critical=True)
    .sign(loaded_privatekey, hashes.SHA256())
	)

	slime_signature = slime_certificate_obj.signature
	slime_signature = int.from_bytes(slime_signature, byteorder='big')
	slime_signature = hex(slime_signature)

	slime_certificate = slime_certificate_obj.public_bytes(serialization.Encoding.PEM)

	x50slime_list = []
	x50slime_list.append(slime_certificate)
	x50slime_list.append(slime_signature)

	# Save the signed certificate to a file
	#with open("certs/" + str(uid) + "_cert.pem", "wb") as ee_file:
	    #ee_file.write(s_slime_certificate)

	return x50slime_list
