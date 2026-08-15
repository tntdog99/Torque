# handles most of the networking for talking to the servers


import json
import csv
import random
from pathlib import Path
import socket
import ssl
import hashlib
import logging
logging.basicConfig(filename='wbms_client.log', level=logging.DEBUG,
                     format='%(asctime)s %(message)s')
def _fingerprint(der_cert_bytes):
    return hashlib.sha256(der_cert_bytes).hexdigest()
def connect_pinned(host, port, expected_fingerprint, timeout=5):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    raw_sock = socket.socket()
    raw_sock.settimeout(timeout)
    raw_sock.connect((host, port))
    conn = context.wrap_socket(raw_sock, server_hostname=host)

    actual = _fingerprint(conn.getpeercert(binary_form=True))
    expected = expected_fingerprint.replace(":", "").lower()
    if actual != expected:
        conn.close()
        raise ssl.SSLCertVerificationError(
            f"Fingerprint mismatch for {host}:{port} — expected {expected}, got {actual}"
        )
    return conn

storage_path = Path(__file__).resolve().parent / ".storage"

def connect_to_all_servers():
    """
    connects to all servers in the server list and returns a list of connections
    """
    with open('serverlist.csv', mode='r', newline='') as file:
        reader = csv.reader(file)
        for server in reader:
            host, port, fp = server
            try:
                conn = connect_pinned(host, int(port), fp)
                yield conn
            except Exception as e:
                logging.exception(f"Could not connect to server {host}:{port} - {e}")
def make_connection_rand():
    """
    reads a random server from the list and tries to connect to it
    """
    
    
    servers = []
    # opens the server list and makes it a list of servers, ports
    with open('serverlist.csv', mode='r', newline='') as file:
        reader = csv.reader(file)
        for server in reader:
            servers.append(server)

    
    max_retrys = len(servers)//2 + 1
    retrys = 0
    while retrys <= max_retrys:
        server = random.choice(servers)
        host, port, fp = server[0], int(server[1]), server[2]
        try:
            return connect_pinned(host, port, fp)
        except (OSError, ssl.SSLError, ssl.SSLCertVerificationError) as e:
            logging.exception(f"Could not connect to {host}:{port} - {e}")
            
        retrys += 1

    raise ConnectionError("Could not connect to any server from serverlist.csv")




def grab_type_from_server(contact_id, type, consume=False):
    """
    grabs a key or message from the server given a contact id and a type of key / message
    """
    
    # this should connect to the server and pull down the requested docs
    request_payload = {
        "request": True, # tells the server that this is a request
        "type_of_key_or_message": type, # the type of key or message
        "contact_id": contact_id, # the contact id / user id
        "consume": consume,
    }
    try:
        connection = make_connection_rand() # grabs a random connection from the list
        with connection:
            connection.sendall(json.dumps(request_payload).encode('utf-8'))
            data = b""
            while True:
                chunk = connection.recv(11534336)
                if not chunk:
                    break
                data += chunk
                if len(data) > 2**20: # 1 MB
                    print('msg too large')
                    break
                try:
                    database_response = json.loads(data.decode())
                    return database_response
                except json.JSONDecodeError:
                    logging.debug("not done")
                    continue
    except (ConnectionError, ssl.SSLError, OSError) as e:
        logging.exception(e)
        raise e
    
def send_to_all_servers(data):
    """
    sends a key or message to the server given a data dict
    """
    for connection in connect_to_all_servers():
        try:
            with connection:
                connection.sendall(json.dumps(data).encode('utf-8'))
                response = connection.recv(1024)
                logging.debug(response.decode())
        except (ConnectionError, ssl.SSLError, OSError) as e:
            logging.exception(e)
            
        
def get_from_all_servers(contact_id, type, consume=False):
    """
    grabs data from all the servers
    """
    
    # this should connect to the server and pull down the requested docs
    request_payload = {
        "request": True, # tells the server that this is a request
        "type_of_key_or_message": type, # the type of key or message
        "contact_id": contact_id, # the contact id / user id
        "consume": consume,
    }
    messages = []
    for connection in connect_to_all_servers():
        try:    
            with connection:
                connection.sendall(json.dumps(request_payload).encode('utf-8'))
                data = b""
                while True:
                    chunk = connection.recv(11534336)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 2**20: # 1 MB
                        print('msg too large')
                        break
                    try:
                        database_response = json.loads(data.decode())
                        for thing in database_response:
                            messages.append(thing)
                    except json.JSONDecodeError:
                        logging.debug("not done")
                        continue
                        
        except (ConnectionError, ssl.SSLError, OSError) as e:
            logging.exception(e)
            continue

    return messages