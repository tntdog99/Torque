from tracemalloc import stop

import messages
import keys
import make_keys
import ratchet
import logging


logging.basicConfig(filename='wbms_client.log', level=logging.DEBUG,
                     format='%(asctime)s %(message)s')
from prompt_toolkit.shortcuts import button_dialog
from prompt_toolkit.shortcuts import input_dialog
from prompt_toolkit.application import get_app
from prompt_toolkit.shortcuts import choice
from prompt_toolkit import prompt
from prompt_toolkit.formatted_text import HTML
import base64
from rich import print as rprint
from cryptography.hazmat.primitives import serialization
import shutil
from pathlib import Path
import textwrap
import json
import os
import time
storage_path = Path(__file__).resolve().parent / ".storage"

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def check_if_starting_keys_exist():
    bundle = Path(storage_path / "pub_bundle.json").is_file()
    return bundle





def grab_contacts() -> list[dict]:
    
    contacts_registry_path = Path(storage_path/"contact_registry.json")
    if not contacts_registry_path.exists():
        contacts_registry_path.write_text('[]')
    contacts_registry_text = contacts_registry_path.read_text()
    contacts_registry_json = json.loads(contacts_registry_text)
    return contacts_registry_json



def grab_blocked_contacts() -> list[str]:
    
    blocked_contact_ids_registry_path = Path(storage_path/"blocked_contact_ids.json")
    if not blocked_contact_ids_registry_path.exists():
        blocked_contact_ids_registry_path.write_text('[]')
    blocked_contact_ids_registry_text = blocked_contact_ids_registry_path.read_text()
    blocked_contact_ids_registry_json = json.loads(blocked_contact_ids_registry_text)
    return blocked_contact_ids_registry_json



def format_choice_contacts(contacts):
    contacts_formatted = []
    for contact in contacts:
        contacts_formatted.append((contact,contact['chat_name']))
    contacts_formatted.append(("new","Add contact"))
    contacts_formatted.append(("refresh","Refresh"))
    return contacts_formatted 



def print_text(columns, message, side):
    
    text = textwrap.wrap(message, int(columns*0.8))
    if not text:
        text = [' ']

    
    max_size = max(len(line) if len(line) != 0 else 1 for line in text)
    
    
    rprint(f'[#000000 on #1f1f1f]')
    
    if side == 'left':
        rprint('═'* max_size+'╗')
    else:
        rprint(f"{' '*(columns-max_size-1)}╔{'═'* max_size}")
    for line in text:
        rprint(calc_size(line, side, columns, max_size))

    if side == 'left':
        rprint('═'* max_size+'╝')
    else:
        rprint(f"{' '*(columns-max_size-1)}╚{'═'* max_size}")
        

def calc_size(text, side, columns, max_size):
    if side == 'left':
        return f'{text:<{max_size}}║{" "*(columns-max_size-1)}'
    if side == 'right':
        return f"{' '*(columns-max_size-1)}║{text:<{max_size}}"








def grab_message_log(my_contact_id, contact_id):
    msg_path = Path(storage_path/"contacts"/contact_id/"messages")
    msg_path_sent = Path(msg_path/'sent')
    msg_path_recv = Path(msg_path/'recv')
    msg_path_recv.mkdir(parents=True, exist_ok=True)
    msg_path_sent.mkdir(parents=True, exist_ok=True)
    our_messages = []
    for file in msg_path_sent.iterdir():
        message = json.loads(file.read_text())
        message['side'] = 'right'
        our_messages.append(message)
    
    try:
        their_messages_raw = keys.get_from_all_servers(my_contact_id, 'message')
    except ConnectionError:
        pass
    temp = []
    for msg in their_messages_raw:
        if msg['_source'] is None:
            continue
        if msg['_source'].get('sender_id') != contact_id:
            continue
        temp.append(msg['_source'])
    their_messages_raw = temp
    their_messages = []
    for raw in their_messages_raw:      
        check_msg_path = Path(msg_path_recv/f'{raw['uuid']}.json')
        if  check_msg_path.exists():
            inner = json.loads(check_msg_path.read_text())
        else:
            _, inner, _ = messages.decode_message(contact_id, raw)
            if inner == None:
                logging.warning(f'inner message is empty')
                continue
            check_msg_path.write_text(json.dumps(inner))
        inner['side'] = 'left'
        their_messages.append(inner)
        
    seen_uuids = []
    their_messages_de_duped = []
    
    for msg in their_messages:
        
        if msg['uuid'] in seen_uuids:
            continue
        else:
            seen_uuids.append(msg['uuid'])
            their_messages_de_duped.append(msg)
    
    
    
    all_messages_compressed = our_messages+their_messages_de_duped
    all_messages_compressed.sort(key=lambda msg: msg['sent_time'])
    all_messages = []
    for message in all_messages_compressed:
        message['message_bytes'] = messages.decompress(base64.urlsafe_b64decode(message["message_bytes"])    , message["compression_type"]).decode()
        all_messages.append(message)
    return all_messages        





def format_message_box(columns, message, side):
    text = textwrap.wrap(message, int(columns * 0.8))
    if not text:
        text = [' ']

    max_size = max(len(line) for line in text)
    lines = []

    if side == 'left':
        lines.append('═' * max_size + '╗')
    else:
        lines.append(f"{' ' * (columns - max_size - 1)}╔{'═' * max_size}")

    for line in text:
        lines.append(calc_size(line, side, columns, max_size))

    if side == 'left':
        lines.append('═' * max_size + '╝')
    else:
        lines.append(f"{' ' * (columns - max_size - 1)}╚{'═' * max_size}")

    return lines

def toolbar():
    text = get_app().current_buffer.text
    columns, _ = shutil.get_terminal_size()

    if not text:
        return "example message box"

    return '\n'.join(format_message_box(columns, text, 'left'))

def message_screen():
    try:
        columns, _ = shutil.get_terminal_size()
        result = prompt("→ ", bottom_toolbar=toolbar, multiline=True)
        return result
    except KeyboardInterrupt:
        return ''
    
    
    
import readchar
import threading
import queue



def contact_screen(contact_bundle, my_contact_id):
    msg_lock = threading.Lock()
    contact_id = contact_bundle['contact_id']
    chat_id = contact_bundle['chat_name']
    message_log  = []
    needs_redraw = threading.Event()
    stop         = threading.Event()
    needs_redraw.set()

    key_queue = queue.Queue()
    key_pause = threading.Event()

    def key_reader(stop_event, key_queue):
        while not stop_event.is_set():
            if key_pause.is_set():
                stop_event.wait(0.05)
                continue
            try:
                key = readchar.readkey()
                key_queue.put(key)
            except KeyboardInterrupt:
                key_queue.put(readchar.key.CTRL_C)
                break
            except Exception as e:
                print(f"Key reader error: {e}")
                break

    def poll(msg_lock):
        while not stop.is_set():
            try:
                new_log = grab_message_log(my_contact_id, contact_id)
                if len(new_log) != len(message_log):
                    with msg_lock:
                        message_log[:] = new_log
                    needs_redraw.set()
            except Exception as e:
                print(f"Poll error: {e}")
            stop.wait(5)
    threading.Thread(target=poll, daemon=True, args=(msg_lock,)).start()
    threading.Thread(target=key_reader, daemon=True, args=(stop, key_queue)).start()

    try:
        while True:
            if needs_redraw.is_set():
                with msg_lock:
                    clear()
                    columns, _ = shutil.get_terminal_size()
                    rprint(f'[#000000 on #ffffff]{chat_id:^{columns}}')
                    rprint(f'[#000000 on #ffffff]{contact_id:^{columns}}')
                    for message in message_log:
                        print_text(columns, message['message_bytes'], message['side'])
                    rprint('[dim]  m  compose    Ctrl+C  back[/dim]')
                needs_redraw.clear()

            try:
                key = key_queue.get_nowait()
                if key == readchar.key.CTRL_C:
                    raise KeyboardInterrupt
            except queue.Empty:
                key = None

            if key is None:
                stop.wait(0.05)
                continue

            if key == readchar.key.CTRL_C:
                break

            if key == 'm':
                key_pause.set()
                try:
                    text = message_screen()
                    if text.strip():
                        outer = messages.encode_message(
                            contact_id, text,
                            base64.urlsafe_b64encode(pubkey_bytes).decode()
                        )
                        keys.send_to_all_servers(json.loads(outer))
                    needs_redraw.set()
                finally:
                    key_pause.clear()
    except KeyboardInterrupt:
        stop.set()
        
    finally:
        stop.set()

    return True



def details_screen(contact_bundle, my_contact_id):
    clear()
    print(f"Name: {contact_bundle['chat_name']}")
    print(f"Contact id: {contact_bundle['contact_id']}")
    option = choice(message="details", options=[('chat', 'Enter'), ('del', 'Delete contact'), ('edit', 'Edit Chat name'), ('block' , 'Block contact')])
    if option == 'chat':
        contact_screen(contact_bundle, my_contact_id)
    if option == 'del':
        contacts = grab_contacts()
        new_contacts = []
        for contact in contacts:
            if contact['contact_id'] != contact_bundle['contact_id']:
                new_contacts.append(contact)
        Path(storage_path/"contact_registry.json").write_text(json.dumps(new_contacts))
    if option == 'edit':
        contacts = grab_contacts()
        new_contacts = []
        for contact in contacts:
            if contact['contact_id'] != contact_bundle['contact_id']:
                new_contacts.append(contact)
            else:
                new_name = input_dialog(title="Edit contact", text="Enter the new chat name: ").run()
                if new_name == None or len(new_name.strip()) == 0:
                    raise KeyboardInterrupt
                contact_bundle['chat_name'] = new_name
                new_contacts.append(contact_bundle)
        Path(storage_path/"contact_registry.json").write_text(json.dumps(new_contacts))
    if option == 'block':
        contacts = grab_contacts()
        new_contacts = []
        for contact in contacts:
            if contact['contact_id'] != contact_bundle['contact_id']:
                new_contacts.append(contact)
        Path(storage_path/"contact_registry.json").write_text(json.dumps(new_contacts))
        
        blocked_contact_ids = grab_blocked_contacts()
        blocked_contact_ids.append(contact_bundle['contact_id'])
        Path(storage_path/"blocked_contact_ids.json").write_text(json.dumps(blocked_contact_ids))
if not check_if_starting_keys_exist():
    make_keys.make_starting_keys()

pubkey = make_keys.grab_identify_keys()[0]
pubkey_bytes = pubkey.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)




def choose_contact():
    global pubkey, pubkey_bytes
    try:

        contacts = grab_contacts()
        contact_choice = choice(message='Choose chat', options=format_choice_contacts(contacts))



        if contact_choice == "new":
            
   
            contact_id = input_dialog(title="Add contact", text="Enter the contact id: ").run()
            if contact_id == None or len(contact_id.strip()) == 0:
                raise KeyboardInterrupt
            new_contact = {"chat_name": contact_id, "contact_id": contact_id}
            contacts.append(new_contact)
            Path(storage_path/"contact_registry.json").write_text(json.dumps(contacts))
            message, state = messages.first_message_send_init(contact_id, "first message", sender_id=base64.urlsafe_b64encode(pubkey_bytes).decode())
            keys.send_to_all_servers(json.loads(message))
            return 'home'
        elif contact_choice == "refresh":
            # grab all the ratchet start messages directed towards the client that the client hasnt gotton yet
            
            

            messages_source = keys.get_from_all_servers(base64.urlsafe_b64encode(pubkey_bytes).decode(), "message")
            if messages_source == None:
                return 'refresh'
            messages_unfilterd = []
            for raw in messages_source:
                messages_unfilterd.append(raw['_source'])
            
            temp = []
            seen_contact_ids = []
            for raw in messages_unfilterd:
                contact_id = raw['sender_id']
                if contact_id in seen_contact_ids:
                    continue
                else:
                    seen_contact_ids.append(contact_id)
                    temp.append(raw)
            messages_unfilterd = temp
            temp = []
            for raw in messages_unfilterd:
                if raw['start'] == True:
                    temp.append(raw)
            messages_unfilterd = temp
            contacts_contact_ids = [contact['contact_id'] for contact in contacts]
            temp = []
            for raw in messages_unfilterd:
                contact_id = raw['sender_id']
                if contact_id not in contacts_contact_ids:
                    temp.append(raw)
            messages_unfilterd = temp

            blocked_contact_ids = grab_blocked_contacts()
            temp = []
            for raw in messages_unfilterd:
                contact_id = raw['sender_id']
                if contact_id not in blocked_contact_ids:
                    temp.append(raw)
            filtered_messages = temp
            del temp
            
            contacts = grab_contacts()
            for message_raw in filtered_messages:
                contact_id = message_raw['sender_id']
                new_contact = {"chat_name": message_raw['sender_id'], "contact_id": message_raw['sender_id']}
                contacts.append(new_contact)
                

                try:
                    inner, _ = messages.first_message_recv_init(contact_id, message_raw, base64.urlsafe_b64encode(pubkey_bytes).decode())
                except ConnectionError:
                    return None
                payload_bytes = base64.urlsafe_b64decode(inner["message_bytes"])
                message = messages.decompress(payload_bytes, inner["compression_type"]).decode()
                recv_path = Path(storage_path/"contacts"/contact_id/"messages"/"recv")
                recv_path.mkdir(parents=True, exist_ok=True)
                Path(recv_path/f'{message_raw["uuid"]}.json').write_text(json.dumps(inner))
                                
                print(message)
            Path(storage_path/"contact_registry.json").write_text(json.dumps(contacts))
            
            
        
        
            
            
            return 'refresh'    
        else:
            return contact_choice
    except KeyboardInterrupt:
        return 'canceled'




def home(default_choice=None):
    global pubkey, pubkey_bytes
    clear()
    contact_id = base64.urlsafe_b64encode(pubkey_bytes).decode()
    print(f"contact id: {contact_id}")
    if default_choice != None:
        menu_choice = default_choice
    else:
        menu_choice = choice(message='Choose chat', options=[
            ('chats', "Contacts"),
            ("new_keys", "Make new keys"),
            
            
        ])
        
    if menu_choice == 'chats':
        clear()
        contact = choose_contact()
        if contact == 'canceled' or contact == 'home':
            return
        if contact == 'refresh':
            return "refresh"
        details_screen(contact, contact_id)
    if menu_choice == 'new_keys':
        contact_path = storage_path/"contacts"/contact_id
        otk_path = contact_path/"otks"
        prekey = make_keys.make_prekey(contact_id)
        keys.send_to_all_servers(prekey)

        make_keys.make_otks(contact_id)

        for otk in otk_path.iterdir():
            otk_data = Path(otk/"semi_pub.json").read_text()
            otk_data = json.loads(otk_data)
            keys.send_to_all_servers(otk_data)
result = None
while True:      
    try:     
        if result == "refresh":
            result = home('chats')
            continue
        result = home()
    except KeyboardInterrupt:
        break