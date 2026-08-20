import base64
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from pathlib import Path

import make_keys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logging.basicConfig(filename='wbms_client.log', level=logging.DEBUG,
                     format='%(asctime)s %(message)s')
logger = logging.getLogger(__name__)

storage_path = Path(__file__).resolve().parent / ".storage"


def make_x25519_pub(key):
    return X25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(key))

def make_x25519_priv(key):
    return X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(key))



class ratchet_state_obj:
    root_key: bytes
    send_chain_key: bytes | None
    recv_chain_key: bytes | None
    ratchet_pub: X25519PublicKey | None
    ratchet_priv: X25519PrivateKey | None
    ratchet_pub_contact: X25519PublicKey | None
    message_number: int
    recv_msg_number: int
    last_chain_length: int
    skipped_message_keys: dict[str, bytes]

    def __init__(
        self,
        root_key,
        send_chain_key,
        recv_chain_key,
        ratchet_pub=None,
        ratchet_priv=None,
        ratchet_pub_contact=None,
        message_number=0,
        recv_msg_number=0,
        last_chain_length=0,
        skipped_message_keys=None
        ):
        skipped_message_keys = skipped_message_keys if skipped_message_keys is not None else {}
        self.root_key = root_key
        self.send_chain_key = send_chain_key
        self.recv_chain_key = recv_chain_key
        self.ratchet_pub = ratchet_pub
        self.ratchet_priv = ratchet_priv
        self.ratchet_pub_contact = ratchet_pub_contact
        self.message_number = message_number
        self.recv_msg_number = recv_msg_number
        self.last_chain_length = last_chain_length
        self.skipped_message_keys = skipped_message_keys
    def save(self, contact_id):
        path = storage_path/"contacts"/contact_id/"ratchet_state.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding='utf-8') as f:
            json.dump(self.export(), f)
        logger.debug("Saved ratchet state for contact %s", contact_id)
    def export(self):
        return {
            "root_key": base64.urlsafe_b64encode(self.root_key).decode(),
            "send_chain_key":
                base64.urlsafe_b64encode(
                    self.send_chain_key
                    ).decode() if self.send_chain_key else None,
            "recv_chain_key":
                base64.urlsafe_b64encode(
                    self.recv_chain_key).decode() if self.recv_chain_key else None,
            "ratchet_pub":
                base64.urlsafe_b64encode(
                    self.ratchet_pub.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                        )
                    ).decode() if self.ratchet_pub else None,
            "ratchet_priv":
                base64.urlsafe_b64encode(
                    self.ratchet_priv.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                        )
                    ).decode() if self.ratchet_priv else None,
            "ratchet_pub_contact":
                base64.urlsafe_b64encode(
                    self.ratchet_pub_contact.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                        )
                    ).decode() if self.ratchet_pub_contact else None,
            "message_number": self.message_number,
            "recv_msg_number": self.recv_msg_number,
            "last_chain_length": self.last_chain_length,
            "skipped_message_keys":
                {k: base64.urlsafe_b64encode(v).decode() for k, v in self.skipped_message_keys.items()}
        }
    def export_ratchet_header(self):
        return {
            "ratchet_pub":
                base64.urlsafe_b64encode(
                    self.ratchet_pub.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                        )
                    ).decode() if self.ratchet_pub else None,
            "message_number": self.message_number,
            "last_chain_length": self.last_chain_length,
        }
def load_ratchet(exported):
    root_key = base64.urlsafe_b64decode(exported["root_key"])
    send_chain_key = base64.urlsafe_b64decode(
        exported["send_chain_key"]
        ) if exported["send_chain_key"] else None
    recv_chain_key = base64.urlsafe_b64decode(
        exported["recv_chain_key"]
        ) if exported["recv_chain_key"] else None
    ratchet_pub = X25519PublicKey.from_public_bytes
    (base64.urlsafe_b64decode(exported["ratchet_pub"])
     ) if exported["ratchet_pub"] else None
    ratchet_priv = X25519PrivateKey.from_private_bytes(
        base64.urlsafe_b64decode(exported["ratchet_priv"])
        ) if exported["ratchet_priv"] else None
    ratchet_pub_contact = X25519PublicKey.from_public_bytes(
        base64.urlsafe_b64decode(exported["ratchet_pub_contact"])
        ) if exported["ratchet_pub_contact"] else None
    message_number = exported["message_number"]
    recv_msg_number = exported["recv_msg_number"]
    last_chain_length = exported["last_chain_length"]

    skipped_message_keys = {k: base64.urlsafe_b64decode(v) for k, v in exported["skipped_message_keys"].items()}

    return ratchet_state_obj(
        root_key,
        send_chain_key,
        recv_chain_key,
        ratchet_pub,
        ratchet_priv,
        ratchet_pub_contact,
        message_number,
        recv_msg_number,
        last_chain_length,
        skipped_message_keys
        )


def initialize_ratchet(contact_id, ratchet_pub, ratchet_priv, new_key, prekey_pub):
    logger.debug("Initializing ratchet for contact %s", contact_id)
    root_key = new_key
    send_chain_key = None
    recv_chain_key = None
    ratchet_pub_contact = prekey_pub
    message_number = 0
    recv_msg_number = 0
    last_chain_length = 0
    skipped_message_keys = {}
    ratchet_state = ratchet_state_obj(
        root_key,
        send_chain_key,
        recv_chain_key,
        ratchet_pub,
        ratchet_priv,
        ratchet_pub_contact,
        message_number,
        recv_msg_number,
        last_chain_length,
        skipped_message_keys
        )
    root, send_chain_key = kdf_root(root_key, ratchet_priv.exchange(prekey_pub))
    ratchet_state.root_key = root
    ratchet_state.send_chain_key = send_chain_key
    return ratchet_state


def initialize_ratchet_recv(contact_id, ratchet_pub, ratchet_priv, new_key):
    logger.debug("Initializing receive-only ratchet state for contact %s", contact_id)
    root_key = new_key
    send_chain_key = None
    recv_chain_key = None
    ratchet_pub_contact = None
    message_number = 0
    recv_msg_number = 0
    last_chain_length = 0
    skipped_message_keys = {}
    ratchet_state = ratchet_state_obj(
        root_key,
        send_chain_key,
        recv_chain_key,
        ratchet_pub,
        ratchet_priv,
        ratchet_pub_contact,
        message_number,
        recv_msg_number,
        last_chain_length,
        skipped_message_keys
        )
    return ratchet_state


def step_ratchet(ratchet_state):
    send_chain_key = ratchet_state.send_chain_key
    msg_key, next_chain_key = kdf_chain(send_chain_key)
    ratchet_state.send_chain_key = next_chain_key
    logger.debug("Advanced send chain for ratchet message number %s", ratchet_state.message_number)
    return msg_key

def ratchet_encrypt(
    ratchet_state: ratchet_state_obj,
    msg,
    contact_id,
    otk_id,
    throw_pub=None,
    start=False,
    lte_pub=None,
    sender_id=None,
    lte_pub_sig=None
    ):
    msg_key = step_ratchet(ratchet_state)
    aesgcm = AESGCM(msg_key)
    nonce = os.urandom(12)
    msg_uuid = str(uuid.uuid4())
    timestamp = time.time()
    header_fields = {
    "ratchet_header": ratchet_state.export_ratchet_header(),
    "contact_id": contact_id,
    "sender_id": sender_id,
    "timestamp": timestamp,
    "uuid": msg_uuid,
    }
    header = json.dumps(header_fields, separators=(',', ':'), sort_keys=True)
    encrypted_payload = aesgcm.encrypt(nonce, msg, header.encode())

    outer_message = {
        "type_of_key_or_message": "message",
        "key_id": otk_id,
        "encrypted_payload": base64.urlsafe_b64encode(encrypted_payload).decode(),
        "header": header,
        "nonce": base64.urlsafe_b64encode(nonce).decode(),
        "throw_pub":
            base64.urlsafe_b64encode(
                throw_pub.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                    )
                ).decode() if throw_pub else None,
        "start": start,
        "lte_sig": lte_pub_sig,
        "lte":
            base64.urlsafe_b64encode(
                lte_pub.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                    )
                ).decode() if lte_pub else None,
    }
    ratchet_state.message_number += 1
    logger.debug(
        "Encrypted ratchet message for contact %s message number %s",
        contact_id,
        ratchet_state.message_number
        )
    return json.dumps(outer_message)


def ratchet_decrypt(ratchet_state, outer_message):
    if isinstance(outer_message, str):
        msg = json.loads(outer_message)
    else:
        msg = outer_message

    full_header = json.loads(msg['header'])
    header = full_header['ratchet_header']
    logger.debug("Ratchet decrypt started for incoming message number %s", header['message_number'])
    header_check = full_header['ratchet_header']
    encrypted_payload = base64.urlsafe_b64decode(msg["encrypted_payload"])
    nonce = base64.urlsafe_b64decode(msg["nonce"])
    incoming_ratchet_pub = header['ratchet_pub']


    skipped_key = ratchet_state.skipped_message_keys.get(
        f"{incoming_ratchet_pub}:{header['message_number']}"
        )
    if skipped_key:
        logger.debug("Using skipped key for retained message %s", header['message_number'])
        del ratchet_state.skipped_message_keys[f"{incoming_ratchet_pub}:{header['message_number']}"]
        return AESGCM(skipped_key).decrypt(nonce, encrypted_payload, header_check.encode())


    current_contact_pub = base64.urlsafe_b64encode(
        ratchet_state.ratchet_pub_contact.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    ).decode()

    if incoming_ratchet_pub is not None and incoming_ratchet_pub != current_contact_pub:
        logger.debug("Performing DH ratchet for new remote ratchet pub")
        if header['last_chain_length'] > 1000:
                logger.warning(
                    "Incoming last_chain_length %s exceeds safety threshold",
                    header['last_chain_length']
                    )
                return None
        for i in range(ratchet_state.recv_msg_number, header['last_chain_length']):
            msg_key, next_chain_key = kdf_chain(ratchet_state.recv_chain_key)
            ratchet_state.skipped_message_keys[f"{current_contact_pub}:{i}"] = msg_key
            ratchet_state.recv_chain_key = next_chain_key


        ratchet_state.last_chain_length = ratchet_state.message_number
        ratchet_state.recv_msg_number = 0
        ratchet_state.message_number = 0
        dh_out = ratchet_state.ratchet_priv.exchange(make_x25519_pub(incoming_ratchet_pub))
        ratchet_state.root_key, ratchet_state.recv_chain_key = kdf_root(
            ratchet_state.root_key,
            dh_out
            )
        ratchet_state.ratchet_pub_contact = make_x25519_pub(incoming_ratchet_pub)
        new_priv, new_pub = make_keys.make_otk()
        ratchet_state.ratchet_priv = new_priv
        ratchet_state.ratchet_pub = new_pub
        dh_out2 = ratchet_state.ratchet_priv.exchange(ratchet_state.ratchet_pub_contact)
        ratchet_state.root_key, ratchet_state.send_chain_key = kdf_root(
            ratchet_state.root_key,
            dh_out2
            )
        logger.debug("DH ratchet complete, reset message counters and derived new chains")


    if header['message_number'] > ratchet_state.recv_msg_number:
        if header['message_number'] > 1000:
            logger.warning(
                "Incoming message_number %s exceeds safety threshold",
                header['message_number']
                )
            return None
        logger.debug(
            "Skipping %s intermediate receive messages",
            header['message_number'] - ratchet_state.recv_msg_number
            )
        for i in range(ratchet_state.recv_msg_number, header['message_number']):
            msg_key, next_chain_key = kdf_chain(ratchet_state.recv_chain_key)
            ratchet_state.skipped_message_keys[f"{incoming_ratchet_pub}:{i}"] = msg_key
            ratchet_state.recv_chain_key = next_chain_key
        ratchet_state.recv_msg_number = header['message_number']


    msg_key, next_chain_key = kdf_chain(ratchet_state.recv_chain_key)
    ratchet_state.recv_chain_key = next_chain_key
    ratchet_state.recv_msg_number += 1
    logger.debug(
        "Decrypted message %s, updated recv_msg_number to %s",
        header['message_number'],
        ratchet_state.recv_msg_number
        )
    return AESGCM(msg_key).decrypt(nonce, encrypted_payload, header_check.encode())



def kdf_root(root_key, dh_output):
    hkdf = HKDF(SHA256(), length=64, salt=root_key, info=b"root")
    output = hkdf.derive(dh_output)
    new_root_key = output[:32]
    new_chain_key = output[32:]
    return new_root_key, new_chain_key




def kdf_chain(chain_key):
    msg_key = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    next_chain_key = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    return msg_key, next_chain_key


