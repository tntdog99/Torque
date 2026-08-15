import socket
import json
import urllib3
import os
import datetime
from pathlib import Path
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import base64


def verify_posted_key(doc):
    try:
        ident_pub = Ed25519PublicKey.from_public_bytes(
            base64.urlsafe_b64decode(doc["contact_id"])
        )
    except Exception:
        return False

    type_of_key = doc.get("type_of_key_or_message")
    try:
        if type_of_key == "otk":
            ident_pub.verify(
                base64.urlsafe_b64decode(doc["otk_signature"]),
                base64.urlsafe_b64decode(doc["public_key"]),
            )
        elif type_of_key == "semi_key":
            ident_pub.verify(
                base64.urlsafe_b64decode(doc["prekey_signature"]),
                base64.urlsafe_b64decode(doc["public_key"]),
            )
            ident_pub.verify(
                base64.urlsafe_b64decode(doc["long_term_encryption_pub_sig"]),
                base64.urlsafe_b64decode(doc["encrypt_pub"]),
            )
        elif type_of_key == "message":
            return True
        else:
            return False  # only signed key types are postable this way
    except (InvalidSignature, KeyError, ValueError):
        return False
    return True

def generate_cert(cn, key_path, cert_path, days=3650):
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)

    Path(key_path).write_bytes(key_bytes)
    Path(cert_path).write_bytes(cert_bytes)

    return cert


def get_fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


key_path = Path("wbms.key")
cert_path = Path("wbms.crt")

if not key_path.exists() or not cert_path.exists():
    print("No cert found, generating new cert")
    cert = generate_cert("wbms", key_path, cert_path, 3650)
    print(f"fingerprint: {get_fingerprint(cert)}")
else:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    print(f"fingerprint: {get_fingerprint(cert)}")

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))







urllib3.disable_warnings()
from elasticsearch import Elasticsearch
api_key = os.environ['API_KEY']

db = Elasticsearch("http://127.0.0.1:9200", api_key=api_key, verify_certs=False)
HOST = '0.0.0.0' 
PORT = 8080




def get_database_entry(id, type):
    query = {
            "query": {
                "bool": {
                    "filter": [
                                { "term": { "type_of_key_or_message.keyword": type } },
                                { "term": { "contact_id.keyword": id } }
                            ]
                        }
                    }
            }
    response = db.search(index="wbms_database", body=query)
    return response["hits"]["hits"]
    
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


server.bind((HOST, PORT))


server.listen()

print(f"Server listening on {HOST}:{PORT}")
while True:
    raw_conn, addr = server.accept()
    try:
        conn = context.wrap_socket(raw_conn, server_side=True)
    except ssl.SSLError as e:
        print(f"TLS handshake failed: {e}")
        raw_conn.close()
        continue
    conn.settimeout(5)
    print("Connected")
    with conn:
        data = b""
        while True:
            chunk = conn.recv(11534336)
            if not chunk:
                break
            # add the chunk to the json packet
            data += chunk
            if len(data) > 2**20: # 1 MB
                print('msg too large')
                break
            try:
                database_request = json.loads(data.decode())
                if database_request.get('request') == True:
                    # grabs the requested data (message or key) from the database
                    if database_request.get('type_of_key_or_message') == 'otk' and database_request.get('consume'):
                        query = {
                            "query": {
                                "bool": {
                                    "filter": [
                                        { "term": { "type_of_key_or_message.keyword": database_request['type_of_key_or_message'] } },
                                        { "term": { "contact_id.keyword": database_request['contact_id'] } }
                                    ]
                                }
                            },
                            "size": 1
                        }
                        response = db.search(index="wbms_database", body=query)
                        hits = response["hits"]["hits"]
                        if len(hits) == 0:
                            sent = []
                        else:
                            sent = [hits[0]]
                            doc_id = hits[0]["_id"]
                            try:
                                db.delete(index="wbms_database", id=doc_id)
                            except Exception as e:
                                print(f"Failed to delete consumed OTK: {e}")
                    elif database_request.get('type_of_key_or_message') == 'otk_invalidate':
                        query = {
                            "query": {
                                "bool": {
                                    "filter": [
                                        {"term": {"type_of_key_or_message.keyword": "otk"}},
                                        {"term": {"contact_id.keyword": database_request['contact_id']}},
                                        {"term": {"key_id.keyword": database_request['key_id']}},
                                    ]
                                }
                            }
                        }
                        db.delete_by_query(index="wbms_database", body=query)
                        conn.sendall(b"invalidated")
                        break
                    else:
                        database_response = get_database_entry(database_request['contact_id'],database_request['type_of_key_or_message'])  
                        if len(database_response) == 0:
                            sent = []
                        else:
                            sent = database_response
                    conn.sendall(json.dumps(sent).encode('utf-8'))
                    break
                else:
                    if not verify_posted_key(database_request):
                        conn.sendall(b"rejected") 
                        break
                    database_response = db.index(index="wbms_database", document=database_request)
                    conn.sendall(b"connected")
                    break
                
            except json.JSONDecodeError:
                # runs if the json packet is not fully received yet
                print("not done")
                continue
            except (KeyError,UnicodeDecodeError, TimeoutError):
                print('malformed input')
                break
            
    print("disconnected")