import socket
import json
import urllib3



import datetime
from pathlib import Path
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
urllib3.disable_warnings()
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
            return False
    except (InvalidSignature, KeyError, ValueError):
        return False
    return True




import sqlite3






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





con = sqlite3.connect("wbms.db")

con.row_factory = sqlite3.Row
cur = con.cursor()

cur.execute(
    """
    CREATE TABLE IF NOT EXISTS wbms_database (
        id INTEGER PRIMARY KEY,
        contact_id TEXT,
        type_of_key_or_message TEXT,
        key_id TEXT,
        document TEXT
    )
    """
)
cur.execute("CREATE INDEX IF NOT EXISTS idx_key_id ON wbms_database(contact_id, key_id)")
con.commit()
HOST = '0.0.0.0' 
PORT = 8080




def format_hits(rows):
    hits = []
    for row in rows:
        try:
            src = json.loads(row["document"])
        except Exception:
            src = {}
        hits.append({"_id": str(row["id"]), "_source": src})
    return hits


def get_database_entry(id, type):
    cur.execute(
        "SELECT id, document FROM wbms_database WHERE contact_id=? AND type_of_key_or_message=?",
        (id, type),
    )
    rows = cur.fetchall()
    return format_hits(rows)
    
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
                    if database_request.get('type_of_key_or_message') == 'otk':
                        cur.execute(
                            "SELECT id, document FROM wbms_database WHERE contact_id=? AND type_of_key_or_message=? LIMIT 1",
                            (database_request['contact_id'], database_request['type_of_key_or_message']),
                        )
                        rows = cur.fetchall()
                        hits = format_hits(rows)
                        if len(hits) == 0:
                            sent = []
                        else:
                            sent = [hits[0]]
                            doc_id = hits[0]["_id"]
                    elif database_request.get('type_of_key_or_message') == 'otk_invalidate':
                        try:
                            key_id = database_request['key_id']
                            invalidate_signature = base64.urlsafe_b64decode(database_request['invalidate_signature'])
                            
                            cur.execute(
                                """
                                SELECT id, contact_id, document
                                FROM wbms_database
                                WHERE type_of_key_or_message = 'otk'
                                AND key_id = ?
                                LIMIT 1
                                """,
                                (database_request["key_id"],),
                            )

                            row = cur.fetchone()


                            otk_document = json.loads(row["document"])
                            otk_public_key = otk_document["makers_public_key"]
                            
                            otk_ident_pub = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(otk_public_key))
                            otk_ident_pub.verify(invalidate_signature, key_id.encode())
                            
                            
                            cur.execute(
                                "DELETE FROM wbms_database WHERE id=?",
                                (row["id"],),
                            )
                            con.commit()
                        except Exception as e:
                            print(f'failed to invalidate OTK: {e}')
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
                    # insert the document into the sqlite table
                    try:
                        if not verify_posted_key(database_request):
                            conn.sendall(b"rejected") 
                            break
                        cur.execute(
                            "INSERT INTO wbms_database (contact_id, type_of_key_or_message, key_id, document) VALUES (?,?,?,?)",
                            (
                                database_request.get('contact_id'),
                                database_request.get('type_of_key_or_message'),
                                database_request.get('key_id'),
                                json.dumps(database_request),
                            ),
                        )
                        con.commit()
                    except Exception as e:
                        print(f"Failed to insert document: {e}")
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