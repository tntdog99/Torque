from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import time

import base64
import json
import os
from pathlib import Path

import logging
logging.basicConfig(filename='wbms_client.log', level=logging.DEBUG,
                     format='%(asctime)s %(message)s')

storage_path = Path(__file__).resolve().parent / ".storage"
def read_long_term_key_bundle():
    bundle = Path(storage_path / "pub_bundle.json").read_text()
    bundle = json.loads(bundle)
    return bundle


def make_prekey(contact_id):
    """
    makes a prekey and saves it to disk
    """
    
    contact_path = storage_path/"contacts"/contact_id
    contact_path.mkdir(parents=True, exist_ok=True)
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
    )
    _, priv_identify_key = grab_identify_keys()
    # signs the prekey with the identify key to prove ownership of the prekey
    prekey_signature = priv_identify_key.sign(public_bytes) # type: ignore
    
    # saves the prekey private key to disk, this is used later when we need to do the x3dh recv
    Path(contact_path/"semi_priv.bin").write_bytes(private_key.private_bytes(encoding=serialization.Encoding.Raw,format=serialization.PrivateFormat.Raw,encryption_algorithm=serialization.NoEncryption()))

    # time stamp of when the key was made
    timestamp = int(time.time())
    
    # generates a random prekey id, this is used to identify the prekey on the server and is also used in the x3dh protocol
    prekey_id = os.urandom(4).hex()
    
    data = {
    "key_id": prekey_id, 
    "contact_id": contact_id,
    "timestamp": timestamp,
    "public_key": base64.urlsafe_b64encode(public_bytes).decode(), # the prekey public key
    "prekey_signature": base64.urlsafe_b64encode(prekey_signature).decode(), # the signature of the prekey public key with the identify key, this is used to prove ownership of the prekey
    "type_of_key_or_message": "semi_key", # the type of key
    "request": False, # post request
    "encrypt_pub": read_long_term_key_bundle()["encrypt_pub"], # the long term encrypt key, this is used in the x3dh protocol
    "long_term_encryption_pub_sig": read_long_term_key_bundle()["long_term_encryption_pub_sig"], # the signature of the long term encrypt key with the identify key, this is used to prove ownership of the long term encrypt key
    }

    Path(contact_path/"semi_pub.json").write_text(json.dumps(data)) # saves the prekey public key and signature to disk, this is used later when we need to do the x3dh send
    return data
        
def make_otks(contact_id):
    """
    makes 50
    otk keys and saves them to contact_path/otks/otk_id
    """
    
    contact_path = storage_path/"contacts"/contact_id
    contact_path.mkdir(parents=True, exist_ok=True)
    for key in range(50):
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
        )
        otk_id = os.urandom(8).hex()
        
        otk_dir = sanitize_path(contact_path/"otks", str(otk_id))
        if otk_dir == None:
            continue
        otk_dir.mkdir(parents=True, exist_ok=True)
        # saves the otk private key to disk, this is used later when we need to do the x3dh recv
        Path(otk_dir/"priv.bin").write_bytes(private_key.private_bytes(encoding=serialization.Encoding.Raw,format=serialization.PrivateFormat.Raw,encryption_algorithm=serialization.NoEncryption()))
        timestamp = int(time.time())
        
        pub_identify_key, priv_identify_key = grab_identify_keys()
        # signs the prekey with the identify key to prove ownership of the prekey
        otk_signature = priv_identify_key.sign(public_bytes) # type: ignore
        
        data = {
        "contact_id": contact_id,
        "key_id": otk_id,
        "timestamp": timestamp,
        "public_key": base64.urlsafe_b64encode(public_bytes).decode(), # the otk public key
        "makers_public_key": base64.urlsafe_b64encode(pub_identify_key.public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)).decode(),
        "otk_signature": base64.urlsafe_b64encode(otk_signature).decode(),
        "type_of_key_or_message": "otk", # the type of key
        "request": False # post request
        }
        # saves the otk public key to disk, this is used later when we need to do the x3dh send
        Path(otk_dir/"semi_pub.json").write_text(json.dumps(data))
            

# makes a single otk
def make_otk():
    """
    makes a otk key
    """
    
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key
            
     
def make_starting_keys():
    """
    makes the long term keys
    """
    
    storage_path.mkdir(parents=True, exist_ok=True)

    identify_priv = ed25519.Ed25519PrivateKey.generate()# signing key
    identify_pub  = identify_priv.public_key()


    encryption_priv = x25519.X25519PrivateKey.generate()# encryption key
    encryption_pub  = encryption_priv.public_key()
    
    
    encrypt_pub_bytes = encryption_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    long_term_encryption_pub_sig = identify_priv.sign(encrypt_pub_bytes)

    (storage_path / "ident_privkey.bin").write_bytes(
        identify_priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    (storage_path / "ident_pubkey.bin").write_bytes(
        identify_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    (storage_path / "encrypt_privkey.bin").write_bytes(
        encryption_priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    )
    json_pub = {
        "encrypt_pub": base64.urlsafe_b64encode(encrypt_pub_bytes).decode(),
        "long_term_encryption_pub_sig": base64.urlsafe_b64encode(long_term_encryption_pub_sig).decode(), # the signature of the long term encrypt key with the identify key, this is used to prove ownership of the long term encrypt key
    }
    (storage_path / "pub_bundle.json").write_text(json.dumps(json_pub))
    
# returns the long term identify keys, this is used to sign the prekeys and otks to prove ownership of the keys
def grab_identify_keys():
    """
    returns the long term signing keys
    """
    
    priv_path = storage_path / "ident_privkey.bin"
    pub_path = storage_path / "ident_pubkey.bin"
    private_key = serialization.load_der_private_key(
        priv_path.read_bytes(),
        password=None
    )
    public_key = serialization.load_der_public_key(
        pub_path.read_bytes()
    )
    return public_key, private_key

# returns the long term encryption keys, this is used in the x3dh protocol
def grab_long_term_encrypttion_keys():
    """
    returns the long term encryption keys
    """
    priv_path = storage_path / "encrypt_privkey.bin"
    private_key = x25519.X25519PrivateKey.from_private_bytes(priv_path.read_bytes())
    public_key = x25519.X25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(read_long_term_key_bundle()["encrypt_pub"]))
                

    return public_key, private_key
def sanitize_path(base_dir, input):
    base = Path(base_dir).resolve()
    target = Path(base, input).resolve()
    if base not in target.parents and base != target:
        return None
    
    return target