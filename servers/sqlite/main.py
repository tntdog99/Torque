from typing_extensions import Dict
import base64
import datetime
import json
import logging
import socket
import sqlite3
import ssl
from pathlib import Path
import argparse
import threading
from queue import Queue
from queue import Full
import time
import copy

import urllib3
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID
logging.basicConfig(filename='wbms_server.log', level=logging.ERROR,
                     format='%(asctime)s %(message)s')
logger: logging.Logger = logging.getLogger(__name__)
urllib3.disable_warnings()


cli_args_parser = argparse.ArgumentParser(description="server software for Torque")
cli_args_parser.add_argument("-i", "--interface", type=str, default="0.0.0.0", help="the interface to bind to")
cli_args_parser.add_argument("-p", "--port", type=int, default=8080, help="the port to bind to")
cli_args_parser.add_argument("-t", "--thread_count", type=int, default=1, help="the amount of threads to start for request handling ")
cli_args_parser.add_argument("-c", "--handler_thread_count", type=int, default=1, help="the amount of threads to start for connection handling ")
cli_args_parser.add_argument("-n", "--timeout", type=int, default=3, help="the time the main thread will wait for a request to be parsed")

args = cli_args_parser.parse_args()


class worker_thread(threading.Thread):
    def __init__(self, request_queue: Queue):
        super().__init__()
        self.sqlite_connection = None
        self.request_queue = request_queue
    def run(self):
        # connect to the database
        self.sqlite_connection = sqlite3.connect("wbms.db")
        self.sqlite_connection.row_factory = sqlite3.Row
        while True:
            
            database_request, connection = self.request_queue.get(block=True, timeout=None)
            worker_cursor: sqlite3.Cursor = self.sqlite_connection.cursor()
            try:
                if database_request.get('request') is True:
                    # grabs the requested data (message or key) from the database
                    if database_request.get('type_of_key_or_message') == 'otk':
                        # fetch otk from contact id of the publisher
                        worker_cursor.execute(
                            "SELECT id, document FROM wbms_database WHERE contact_id=? AND type_of_key_or_message=? LIMIT 1",
                            (database_request['contact_id'],
                            database_request['type_of_key_or_message']),# always otk
                        )
                        rows = worker_cursor.fetchall()
                        hits = format_hits(rows)
                        if len(hits) == 0:
                            sent = []
                        else:
                            sent = [hits[0]]
                            doc_id = hits[0]["_id"]
                    elif database_request.get('type_of_key_or_message') == 'otk_invalidate':
                        try:
                            key_id = database_request['key_id']
                            invalidate_signature = base64.urlsafe_b64decode(
                                database_request['invalidate_signature']
                                )

                            worker_cursor.execute(
                                """
                                SELECT id, contact_id, document
                                FROM wbms_database
                                WHERE type_of_key_or_message = 'otk'
                                AND key_id = ?
                                LIMIT 1
                                """,
                                (database_request["key_id"],),
                            )

                            row = worker_cursor.fetchone()


                            otk_document = json.loads(row["document"])
                            otk_public_key = otk_document["makers_public_key"]

                            otk_ident_pub = Ed25519PublicKey.from_public_bytes(
                                base64.urlsafe_b64decode(otk_public_key)
                                )
                            otk_ident_pub.verify(invalidate_signature, key_id.encode())


                            worker_cursor.execute(
                                "DELETE FROM wbms_database WHERE id=?",
                                (row["id"],),
                            )
                            self.sqlite_connection.commit()

                        except Exception as e:
                            logger.info('failed to invalidate OTK: %s', e)
                        connection.sendall(b"invalidated")
                        continue
                    else:
                        if database_request.get('type_of_key_or_message') == 'semi_key':
                            worker_cursor.execute(
                                "SELECT id, document FROM wbms_database WHERE contact_id=? AND type_of_key_or_message=? ORDER BY id DESC LIMIT 1",
                                (database_request['contact_id'], database_request['type_of_key_or_message']),
                            )
                        else:
                            worker_cursor.execute(
                                "SELECT id, document FROM wbms_database WHERE contact_id=? AND type_of_key_or_message=?",
                                (database_request['contact_id'], database_request['type_of_key_or_message']),
                            )
                        rows = worker_cursor.fetchall()
                        database_response = format_hits(rows)

                        if len(database_response) == 0:
                            sent = []
                        else:
                            sent = database_response
                    connection.sendall(json.dumps(sent).encode('utf-8'))
                    continue
                else:
                    # insert the document into the sqlite table
                    try:
                        if not verify_posted_key(database_request):
                            logger.warning("Invalid signature for document: %s", database_request)

                            connection.sendall(b"rejected")
                            continue
                        worker_cursor.execute(
                            "INSERT INTO wbms_database (contact_id, type_of_key_or_message, key_id, document) VALUES (?,?,?,?)",
                            (
                                database_request.get('contact_id'),
                                database_request.get('type_of_key_or_message'),
                                database_request.get('key_id'),
                                json.dumps(database_request),
                            ),
                        )
                        self.sqlite_connection.commit()
                    except Exception as e:
                        logger.info("Failed to insert document: %s", e)
                    connection.sendall(b"connected")
                    continue
            except (OSError, ssl.SSLError) as e:
                logger.info("client disconnected before response: %s", e)
            finally:
                worker_cursor.close()
                connection.close()



def verify_posted_key(doc):



    doc = copy.deepcopy(doc)
    type_of_key = doc.get("type_of_key_or_message")


    try:
        if type_of_key == "message":
            ident_pub: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(
                base64.urlsafe_b64decode(doc["sender_id"])
            )
        else:
            ident_pub: Ed25519PublicKey = Ed25519PublicKey.from_public_bytes(
                base64.urlsafe_b64decode(doc["contact_id"])
            )
    except Exception:
        return False



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
            outer_message_signature = base64.urlsafe_b64decode(doc.pop("outer_message_signature", None))
            original_signed_outer_message = json.dumps(doc, separators=(',', ':'), sort_keys=True).encode("utf-8")
            ident_pub.verify(
                outer_message_signature,
                original_signed_outer_message
            )
    except (InvalidSignature, KeyError, ValueError):
        return False
    return True

def generate_cert(cn, key_path, cert_path, days=3650):
    key: rsa.RSAPrivateKey = rsa.generate_private_key(public_exponent=65537, key_size=4096)

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
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
            )
        .sign(key, hashes.SHA256())
    )

    key_bytes: bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_bytes: bytes = cert.public_bytes(serialization.Encoding.PEM)

    Path(key_path).write_bytes(key_bytes)
    Path(cert_path).write_bytes(cert_bytes)

    return cert


def get_fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


key_path = Path("wbms.key")
cert_path = Path("wbms.crt")

if not key_path.exists() or not cert_path.exists():
    logger.warning("No cert found, generating new cert")
    cert = generate_cert("wbms", key_path, cert_path, 3650)
else:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
print("fingerprint: ", get_fingerprint(cert))
logger.info("fingerprint: %s", get_fingerprint(cert))

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))





setup_connection_sqlite: sqlite3.Connection = sqlite3.connect("wbms.db")

setup_connection_sqlite.row_factory = sqlite3.Row
cursor: sqlite3.Cursor = setup_connection_sqlite.cursor()

cursor.execute(
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
cursor.execute("CREATE INDEX IF NOT EXISTS idx_key_id ON wbms_database(contact_id, key_id)")
setup_connection_sqlite.commit()
setup_connection_sqlite.close()
HOST = args.interface
PORT = args.port



def format_hits(rows):
    hits: list[Dict] = []
    for row in rows:
        try:
            src = json.loads(row["document"])
        except Exception:
            src = {}
        hits.append({"_id": str(row["id"]), "_source": src})
    return hits




server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


server.bind((HOST, PORT))

request_queue = Queue(maxsize=500)
request_threads = []

for _ in range(args.thread_count):
    thread = worker_thread(request_queue=request_queue)
    request_threads.append(thread)
    thread.start()
    
    
logger.info('started worker threads')
server.listen()

logger.info("Server listening on %s:%s", HOST, PORT)
connection_queue = Queue(maxsize=200)

def connection_handler(connection_queue, request_queue):
    while True:
        non_tls_connection = connection_queue.get()
        non_tls_connection.settimeout(args.timeout)

        try:
            connection: ssl.SSLSocket = context.wrap_socket(non_tls_connection, server_side=True)
        except ssl.SSLError as e:
            logger.info("TLS handshake failed: %s", e)
            non_tls_connection.close()
            continue
        connection.settimeout(args.timeout)
        logger.info("Connected")
        start_time: float = time.time()
        handed_to_worker = False
        data = b""
        while True:
            try:
                json_chunk_bytes: bytes = connection.recv(11534336)
                if not json_chunk_bytes:
                    break
                # add the chunk to the json packet
                data += json_chunk_bytes
                if len(data) > 2**20: # 1 MB
                    logger.info('msg too large')
                    break
                try:
                    database_request = json.loads(data.decode())
                    request_queue.put((database_request, connection), timeout=5)
                    handed_to_worker = True
                    break
                except json.JSONDecodeError:
                    if time.time() - start_time > args.timeout:
                        raise TimeoutError
                    # runs if the json packet is not fully received yet
                    logger.info("not done")
                    continue
                except (KeyError,UnicodeDecodeError):
                    if time.time() - start_time > args.timeout:
                        raise TimeoutError
                    logger.info('malformed input')
                    break
            except (TimeoutError):
                logger.info('timeout')
                break
        if not handed_to_worker:
            connection.close()

for _ in range(args.handler_thread_count):
    threading.Thread(target=connection_handler, args=(connection_queue, request_queue), daemon=True).start()


while True:
    raw_connection, addr = server.accept()
    try:
        connection_queue.put_nowait(raw_connection)
    except Full:
        raw_connection.close()
