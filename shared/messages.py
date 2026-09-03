import base64
import gzip
import json
import logging
import lzma
import time
import uuid
from pathlib import Path

import keys
import make_keys
import ratchet
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# inner message



# sent time: utc

# part number, {sent-amount}: int

# compression type, (lzma, gzip): string

# payload type, (text, file), string

# message bytes, {compressed (compression type)}: bytes

# type: str > message



# outer message

# contact_id

# sent time: utc


# encrypted payload: bytes


# rachet header : str(json)



# type: str > message



storage_path = Path(__file__).resolve().parent / ".storage"

logging.basicConfig(filename='wbms_client.log', level=logging.DEBUG,
                     format='%(asctime)s %(message)s')
logger = logging.getLogger(__name__)




def X3DH(long_term_encrypttion_priv , prekey_pub , otk_pub , long_term_encrypttion_pub):
    """
    returns a shared key and a throwaway public key for the initiator to use in the x3dh recv function
    """

    throw_priv, throw_pub = make_keys.make_otk()

    new_key_one = long_term_encrypttion_priv.exchange(prekey_pub)
    new_key_two = throw_priv.exchange(long_term_encrypttion_pub)
    new_key_three = throw_priv.exchange(prekey_pub)
    new_key_four = throw_priv.exchange(otk_pub)

    combined = new_key_one+new_key_two+new_key_three+new_key_four


    new_key = HKDF(SHA256(),length=32,salt=b"\x00"*32,info=b"X3DH").derive(combined)

    return throw_pub, new_key




def X3DH_recv(
    prekey_priv,
    long_term_encrypttion_priv,
    otk_priv,
    initiator_long_term_encrypttion_pub,
    initiator_throw_pub
    ):
    """
    takes the keys and returns the shared key for the receiver
    """



    new_key_one = prekey_priv.exchange(initiator_long_term_encrypttion_pub)
    new_key_two = long_term_encrypttion_priv.exchange(initiator_throw_pub)
    new_key_three = prekey_priv.exchange(initiator_throw_pub)
    new_key_four = otk_priv.exchange(initiator_throw_pub)

    combined = new_key_one + new_key_two + new_key_three + new_key_four
    new_key = HKDF(SHA256(), length=32, salt=b"\x00"*32, info=b"X3DH").derive(combined)

    return new_key




def check_sig(signature, signed_data, verifying_key: Ed25519PublicKey):
    try:
        verifying_key.verify(
            base64.urlsafe_b64decode(signature),
            base64.urlsafe_b64decode(signed_data)
            )
    except InvalidSignature:
        logger.warning("Signature verification failed")
        raise InvalidSignature("uh oh..")


def make_x25519_pub(key):
    """
    returns a x25519 public key object from a base64 encoded string of the raw public key bytes
    """

    return X25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(key))

def make_x25519_priv(key):
    """
    returns a x25519 private key object from a base64 encoded string of the raw private key bytes
    """

    return X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(key))



class NoKeyFound(Exception):
    pass

def compress(data, compression_type):
    """
    compresses the data using the specified compression type (gzip or lzma)
    """

    if compression_type == "gzip":
        return gzip.compress(data)
    elif compression_type == "lzma":
        return lzma.compress(data)
    else:
        raise ValueError("Unsupported compression type")


def decompress(data, compression_type):
    """
    decompresses the data using the specified compression type (gzip or lzma)
    """

    if compression_type == "gzip":

        return gzip.decompress(data)
    elif compression_type == "lzma":
        return lzma.decompress(data)
    else:
        raise ValueError("Unsupported compression type")





def make_inner_message(
    contact_id, payload,
    compression_type="gzip",
    payload_type="text",
    part_number=1
    ):
    inner_message = {
        "sent_time": int(time.time()),
        'uuid': str(uuid.uuid4()),
        "part_number": part_number, # part number of the message in case it comes in more then one part
        "compression_type": compression_type,
        "payload_type": payload_type,
        "message_bytes": base64.urlsafe_b64encode(
            compress(payload.encode(),
                     compression_type)
            ).decode(),
        "type_of_key_or_message": "message"
    }
    Path(storage_path/"contacts"/contact_id/"messages"/'sent').mkdir(parents=True, exist_ok=True)
    msg_path = Path(
        storage_path/"contacts"/contact_id/"messages"/'sent'/f"{int(time.time())!s}{uuid.uuid4()!s}.json"
        )
    msg_path.write_text(json.dumps(inner_message), encoding='utf-8')
    return inner_message

def consume_otk(key_id, contact_id):
    _, my_ident_priv = make_keys.grab_identify_keys()
    keys.send_to_all_servers({
        "type_of_key_or_message": "otk_invalidate",
        "contact_id": contact_id,
        "key_id": key_id,
        "invalidate_signature": base64.urlsafe_b64encode(my_ident_priv.sign(key_id.encode())).decode(), # type: ignore
        "request": False,
    })

def first_message_send_init(contact_id, message, sender_id):
    inner = make_inner_message(contact_id, message)
    _, identify_priv = make_keys.grab_identify_keys()


    logger.debug("Starting first message send init for contact %s", contact_id)
    verifying_key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(contact_id))

    try:
        prekey_bundle = keys.grab_type_from_server(contact_id, "semi_key")[0]['_source'] # type: ignore
    except (IndexError,TypeError) as e:
        logger.error("No semi_key found for contact %s", contact_id)
        raise NoKeyFound("no otk key found on server") from e

    try:
        otk_json = keys.grab_type_from_server(contact_id, "otk")[0]['_source'] # type: ignore
    except (IndexError,TypeError) as e:
        logger.error("No otk found for contact %s", contact_id)
        raise NoKeyFound("no pre key found on server") from e

    if otk_json is None:
        logger.error("Empty otk payload for contact %s", contact_id)
        raise NoKeyFound("no otk key found on server")
    if prekey_bundle is None:
        logger.error("Empty semi_key payload for contact %s", contact_id)
        raise NoKeyFound("no pre key found on server")

    check_sig(
        prekey_bundle['long_term_encryption_pub_sig'],
        prekey_bundle['encrypt_pub'],
        verifying_key
        )
    check_sig(prekey_bundle['prekey_signature'], prekey_bundle['public_key'], verifying_key)
    check_sig(otk_json['otk_signature'], otk_json['public_key'], verifying_key)
    logger.debug("Validated signatures for contact %s", contact_id)
    long_term_ident_encrypt = make_x25519_pub(prekey_bundle["encrypt_pub"])#grabs their long term encrypt key

    prekey_pub = make_x25519_pub(prekey_bundle["public_key"])#grabs their prekey

    otk = make_x25519_pub(otk_json["public_key"])#grabs their otk
    lte_pub, lte_priv = make_keys.grab_long_term_encrypttion_keys()#grabs our lte keys

    encrypt_pub_bytes = lte_pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
        )
    long_term_encryption_pub_sig = identify_priv.sign(encrypt_pub_bytes)  # type: ignore

    throw_pub, new_key = X3DH(lte_priv,prekey_pub, otk, long_term_ident_encrypt)
    ratchet_priv, ratchet_pub = make_keys.make_otk()
    ratchet_state = ratchet.initialize_ratchet(
        contact_id,
        ratchet_pub,
        ratchet_priv,
        new_key,
        prekey_pub
        )
    outer_message = ratchet.ratchet_encrypt(
        ratchet_state,
        json.dumps(inner).encode(),
        contact_id, otk_json['key_id'],
        throw_pub, start=True,
        lte_pub=lte_pub,
        sender_id=sender_id,
        lte_pub_sig=long_term_encryption_pub_sig
        )
    ratchet_state.save(contact_id)
    return outer_message, ratchet_state


def first_message_recv_init(contact_id, msg, my_contact_id):

    contact_path = storage_path/"contacts"/my_contact_id
    try:
        verifying_key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(contact_id))
    except ValueError:
        logger.error("Invalid contact_id format for contact %s", contact_id)
        return None, None
    prekey_priv = Path(contact_path/"semi_priv.bin").read_bytes()
    prekey_priv = X25519PrivateKey.from_private_bytes(prekey_priv)



    # make sure the format of the message is correct
    
    try:
        # pylint: disable=pointless-statement
        msg['lte_sig']
        msg['lte']
        msg['key_id']
        msg['encrypted_payload']
        msg['header']
        msg['nonce']
        msg['throw_pub']
        full_header = json.loads(msg['header'])
        full_header['ratchet_header']
        full_header['ratchet_header']['ratchet_pub']
        # pylint: enable=pointless-statement
    except (KeyError, json.JSONDecodeError) as e:
        logger.exception("Missing key or invalid json in message for contact %s: %s", contact_id, e)
        return None, None


    try:
        check_sig(msg['lte_sig'], msg['lte'], verifying_key)
    except InvalidSignature:
        return None, None
    otk_id = msg["key_id"]

    payload = base64.urlsafe_b64decode(msg["encrypted_payload"])

    full_header = json.loads(msg['header'])

    header = full_header['ratchet_header']

    nonce = base64.urlsafe_b64decode(msg['nonce'])

    _, lte_priv = make_keys.grab_long_term_encrypttion_keys()

    lte_other_pub = make_x25519_pub(msg['lte'])
    throw_pub = make_x25519_pub(msg["throw_pub"])

    prekey_path = contact_path/"semi_pub.json"
    prekey_bundle = json.loads(prekey_path.read_text(encoding='utf-8'))


    prekey_pub = make_x25519_pub(prekey_bundle["public_key"])


    otk_path = make_keys.sanitize_path(contact_path/"otks", str(otk_id))
    if otk_path is None:
        return None, None
    otk_priv = X25519PrivateKey.from_private_bytes(Path(otk_path/"priv.bin").read_bytes())
    new_key = X3DH_recv(prekey_priv, lte_priv, otk_priv, lte_other_pub, throw_pub)


    new_priv, new_pub = make_keys.make_otk()
    ratchet_state = ratchet.initialize_ratchet_recv(
        contact_id,
        new_pub,
        new_priv,
        new_key,
        prekey_pub,
        )
    ratchet_state.ratchet_pub_contact = make_x25519_pub(header['ratchet_pub'])

    new_thing = prekey_priv.exchange(ratchet_state.ratchet_pub_contact)
    ratchet_state.root_key, ratchet_state.recv_chain_key = ratchet.kdf_root(ratchet_state.root_key, new_thing)



    ratchet_state.ratchet_priv = new_priv
    ratchet_state.ratchet_pub = new_pub
    dh_out2 = ratchet_state.ratchet_priv.exchange(ratchet_state.ratchet_pub_contact)
    ratchet_state.root_key, ratchet_state.send_chain_key = ratchet.kdf_root(ratchet_state.root_key, dh_out2)




    msg_key, ratchet_state.recv_chain_key = ratchet.kdf_chain(ratchet_state.recv_chain_key)

    aesgcm = AESGCM(msg_key)


    aad = json.dumps(
    full_header,
    separators=(",", ":"),
    sort_keys=True,
    )
    try:
        decrypted_payload = aesgcm.decrypt(nonce, payload, aad.encode("utf-8"))
    except InvalidTag:
        logger.debug("Failed to decrypt message for contact %s", contact_id)
        return None, None

    logger.debug("Successfully decrypted first message for contact %s", contact_id)


    ratchet_state.recv_msg_number += 1
    ratchet_state.save(contact_id)


    otk_dir = make_keys.sanitize_path(contact_path/"otks", str(otk_id))
    if otk_dir is None:
        return None, None
    consume_otk(otk_id, contact_id)
    Path(otk_dir/"semi_pub.json").unlink()
    Path(otk_dir/"priv.bin").unlink()

    return json.loads(decrypted_payload.decode()), ratchet_state



def decode_message(contact_id, outer_message):

    contact_path = storage_path/"contacts"/contact_id
    ratchet_state = ratchet.load_ratchet(
        json.loads((contact_path/"ratchet_state.json").read_text(encoding='utf-8'))
        )



    try:
        decrypted = ratchet.ratchet_decrypt(ratchet_state, outer_message)
    except InvalidTag:
        print('invalid sig')
        return None, None, None
    if decrypted is None:
        return None, None, None
    ratchet_state.save(contact_id)
    inner = json.loads(decrypted.decode())
    payload_bytes = base64.urlsafe_b64decode(inner["message_bytes"])
    payload = decompress(payload_bytes, inner["compression_type"]).decode()
    return payload, inner, ratchet_state

def encode_message(contact_id, message, sender_id):
    inner = make_inner_message(contact_id, message)

    contact_path = storage_path/"contacts"/contact_id
    ratchet_state = ratchet.load_ratchet(
        json.loads((contact_path/"ratchet_state.json").read_text(encoding='utf-8'))
        )

    logger.debug("Encoding regular message for contact %s", contact_id)
    _, identify_priv = make_keys.grab_identify_keys()
    lte_pub, _ = make_keys.grab_long_term_encrypttion_keys()
    encrypt_pub_bytes = lte_pub.public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw
    )
    long_term_encryption_pub_sig = identify_priv.sign(encrypt_pub_bytes) # type: ignore
    outer_message = ratchet.ratchet_encrypt(
        ratchet_state,
        json.dumps(inner).encode(),
        contact_id,
        None, None,
        sender_id=sender_id,
        lte_pub_sig=long_term_encryption_pub_sig,
        )
    ratchet_state.save(contact_id)
    logger.debug("Encoded regular message for contact %s", contact_id)
    return outer_message