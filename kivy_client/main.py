import base64
import json
import os
import threading
from pathlib import Path
from typing import Any

import keys
import kivy
import make_keys
import messages
from cryptography.hazmat.primitives import serialization
from kivy.app import App
from kivy.clock import Clock
from kivy.graphics import Color, RoundedRectangle
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.widget import Widget

kivy.require('2.3.1')




# TODO parity changes:

# add a chat details in between the chat screen and contact select screen

# add a "delete contact" button to the chat popup
# add a "rename contact" button to the chat popup
# add a "block contact" button to the chat popup

# add a refresh button to the contact list popup




storage_path = Path(__file__).resolve().parent / ".storage"

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')


def check_if_starting_keys_exist():
    bundle = Path(storage_path / "pub_bundle.json").is_file()
    return bundle

def new_keys(_):
    contact_id = base64.urlsafe_b64encode(pubkey_bytes).decode()
    contact_path = storage_path/"contacts"/contact_id
    otk_path = contact_path/"otks"
    prekey = make_keys.make_prekey(contact_id)
    keys.send_to_all_servers(prekey)

    make_keys.make_otks(contact_id)

    for otk in otk_path.iterdir():
        otk_data = Path(otk/"semi_pub.json").read_text(encoding='utf-8')
        otk_data = json.loads(otk_data)
        keys.send_to_all_servers(otk_data)
    clear()




def grab_contacts() -> list[dict]:

    contacts_registry_path = Path(storage_path/"contact_registry.json")
    if not contacts_registry_path.exists():
        contacts_registry_path.write_text('[]')
    contacts_registry_text = contacts_registry_path.read_text(encoding='utf-8')
    contacts_registry_json = json.loads(contacts_registry_text)
    return contacts_registry_json



if not check_if_starting_keys_exist():
    make_keys.make_starting_keys()

pubkey = make_keys.grab_identify_keys()[0]
pubkey_bytes = pubkey.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)













def grab_message_log(my_contact_id, contact_id):
    msg_path = Path(storage_path/"contacts"/contact_id/"messages")
    msg_path_sent = Path(msg_path/'sent')
    msg_path_recv = Path(msg_path/'recv')
    msg_path_recv.mkdir(parents=True, exist_ok=True)
    msg_path_sent.mkdir(parents=True, exist_ok=True)
    our_messages = []
    for file in msg_path_sent.iterdir():
        message = json.loads(file.read_text(encoding='utf-8'))
        message['side'] = 'right'
        our_messages.append(message)

    their_messages_raw = keys.get_from_all_servers(my_contact_id, 'message')
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
        check_msg_path = Path(msg_path_recv/f'{raw["uuid"]}.json')
        if  check_msg_path.exists():
            inner = json.loads(check_msg_path.read_text(encoding='utf-8'))
        else:
            _, inner, _ = messages.decode_message(contact_id, raw)
            if inner is None:
                continue
            check_msg_path.write_text(json.dumps(inner))
        inner['side'] = 'left'
        their_messages.append(inner)

    seen_uuids = []
    their_messages_de_duped = []

    for msg in their_messages:

        if msg['uuid'] in seen_uuids:
            continue
        seen_uuids.append(msg['uuid'])
        their_messages_de_duped.append(msg)



    all_messages_compressed = our_messages+their_messages_de_duped
    all_messages_compressed.sort(key=lambda msg: msg['sent_time'])
    all_messages = []
    for message in all_messages_compressed:
        message['message_bytes'] = messages.decompress(
            base64.urlsafe_b64decode(message["message_bytes"]),
            message["compression_type"]
            ).decode()
        all_messages.append(message)
    return all_messages






class MessageBubble(BoxLayout):

    def __init__(self, text, is_mine, **kwargs):
        super().__init__(
            orientation='horizontal',
            size_hint_y=None,
            padding=[6, 4],
            **kwargs
        )

        bubble: Any = Label(
            text=text,
            size_hint_x=0.65,
            size_hint_y=None,
            halign='left',
            valign='top',
            color=(1, 1, 1, 1),
        )

        bubble.bind(
            width=lambda bubble, new_width: setattr(bubble, 'text_size', (new_width - 20, None))
            )

        def _update_heights(bubble, tex_size):
            bubble.height = tex_size[1] + 16
            self.height = bubble.height + 8

        bubble.bind(texture_size=_update_heights)

        with bubble.canvas.before:
            if is_mine:
                Color(0.22, 0.55, 0.95, 1)
            else:
                Color(0.28, 0.28, 0.28, 1)
            bg_rect = RoundedRectangle(pos=bubble.pos, size=bubble.size, radius=[10])

        bubble.bind(pos=lambda *_: setattr(bg_rect, 'pos', bubble.pos))
        bubble.bind(size=lambda *_: setattr(bg_rect, 'size', bubble.size))

        spacer = Widget(size_hint_x=0.35)

        if is_mine:
            self.add_widget(spacer)
            self.add_widget(bubble)
        else:
            self.add_widget(bubble)
            self.add_widget(spacer)








class chat_popup(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', padding=20, spacing=10, **kwargs)
        self.msg_lock = threading.Lock()
        self.popup = None
        self.update_messages_event = None

        # header

        self.hotbar_header = BoxLayout(
            orientation='horizontal',
            spacing=8,
            size_hint_y=None,
            height=48,
        )

        spacer = Widget(size_hint_x=0.8)
        self.delete_button = Button(text='Delete', on_press=self.delete_contact)

        self.hotbar_header.add_widget(spacer)
        self.hotbar_header.add_widget(self.delete_button)


        self.chat_id_label = Label(text='placeholder', size_hint_y=None, height=30)
        self.contact_id_label = Label(text='placeholder', size_hint_y=None, height=30)

        self.add_widget(self.chat_id_label)
        self.add_widget(self.contact_id_label)

        self.scroll = ScrollView()
        self.message_list: Any = BoxLayout(
            orientation='vertical',
            spacing=8,
            size_hint_y=None,
        )
        self.message_list.bind(minimum_height=self.message_list.setter('height'))
        self.scroll.add_widget(self.message_list)
        self.add_widget(self.scroll)

        self.message_input = TextInput(size_hint=(.7, 1), multiline=False)
        self.send_button = Button(
            text='Send',
            size_hint=(.3, 1),
            on_press=self.send_message,
        )

        self.message_input_layout = BoxLayout(
            orientation='horizontal',
            spacing=8,
            size_hint_y=None,
            height=48,
        )
        self.message_input_layout.add_widget(self.message_input)
        self.message_input_layout.add_widget(self.send_button)
        self.add_widget(self.message_input_layout)


    def load(self, contact_bundle):
        self.contact_bundle = contact_bundle
        self.my_contact_id = base64.urlsafe_b64encode(pubkey_bytes).decode()

        self.message_log = []

        self.contact_id = contact_bundle['contact_id']
        self.chat_id = contact_bundle['chat_name']

        self.chat_id_label.text = self.chat_id
        self.contact_id_label.text = self.contact_id

        if self.update_messages_event:
            self.update_messages_event.cancel()
        self.update_messages_event = Clock.schedule_interval(self.update_messages, 5.0)

        self.popup: Any = Popup(title=self.chat_id, content=self)
        self.popup.bind(on_dismiss=self.on_dismiss)
        self.popup.open()
        self.redraw(0)

    def send_message(self, instance):
        text = self.message_input.text
        if text.strip():
            outer = messages.encode_message(
                self.contact_id, text,
                base64.urlsafe_b64encode(pubkey_bytes).decode()
            )
            keys.send_to_all_servers(json.loads(outer))
            self.message_input.text = ''

    def redraw(self, dt):
        self.message_list.clear_widgets()
        with self.msg_lock:
            log_copy = list(self.message_log)
        for msg in log_copy:
            is_mine = msg['side'] == 'right'
            bubble = MessageBubble(text=msg['message_bytes'], is_mine=is_mine)
            self.message_list.add_widget(bubble)
        Clock.schedule_once(self._scroll_to_bottom, 0.05)

    def update_messages(self, dt):
        new_log = grab_message_log(self.my_contact_id, self.contact_id)
        if len(new_log) != len(self.message_log):
            with self.msg_lock:
                self.message_log = new_log
            Clock.schedule_once(self.redraw, 1)

    def _scroll_to_bottom(self, dt):
        self.scroll.scroll_y = 0

    def on_dismiss(self, *args):
        if self.update_messages_event:
            self.update_messages_event.cancel()
            self.update_messages_event = None



    def delete_contact(self, _):
        contacts = grab_contacts()
        new_contacts = []
        for contact in contacts:
            if contact['contact_id'] != self.contact_bundle['contact_id']:
                new_contacts.append(self.contact_bundle)
        Path(storage_path/"contact_registry.json").write_text(json.dumps(new_contacts))


        self.popup.dismiss()

class choose_contact_popup(BoxLayout):
    # this entire class is a ******* mess and i hate it, should i try and fix it? maybe, but i wont

    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', padding=20, spacing=10, **kwargs)
        self.popup = None
        self.form_popup = None

        self.contact_list: Any = BoxLayout(
            orientation='vertical',
            spacing=8,
            size_hint_y=None
        )
        self.contact_list.bind(minimum_height=self.contact_list.setter('height'))

        scroll = ScrollView()
        scroll.add_widget(self.contact_list)
        self.add_widget(scroll)

        self.load_contacts()

    def load_contacts(self):
        self.contact_list.clear_widgets()
        contacts = grab_contacts()





        for contact in contacts:
            button: Any = Button(
                text=contact['chat_name'],
                size_hint_y=None,
                height=50
            )
            button.bind(on_press=lambda instance, c=contact: self.open_contact(c))
            self.contact_list.add_widget(button)

        add_btn: Any = Button(text="Add Contact", size_hint_y=None, height=50)




        add_btn.bind(on_press=self.add_contact)
        self.contact_list.add_widget(add_btn)

    def open(self):
        self.load_contacts()
        self.popup = Popup(title='Contacts', content=self)
        self.popup.open()

    def open_contact(self, contact):
        if self.popup:
            self.popup.dismiss()
        chat = chat_popup()
        chat.load(contact)

    def add_contact(self, instance):
        layout = BoxLayout(orientation='vertical', padding=20, spacing=10)

        chat_name = TextInput(multiline=False, hint_text='chat name')
        layout.add_widget(chat_name)
        self.add_contact_chat_name = chat_name
        contact_id = TextInput(multiline=False, hint_text='contact id')
        layout.add_widget(contact_id)
        self.add_contact_contact_id = contact_id

        layout_two = BoxLayout(orientation='horizontal', padding=20, spacing=10)
        send = Button(text='Send', on_press=self.add_contact_final_send)
        layout_two.add_widget(send)
        recv = Button(text='Recv', on_press=self.add_contact_final_recv)
        layout_two.add_widget(recv)
        layout.add_widget(layout_two)

        self.form_popup = Popup(title="Add Contact", content=layout, size_hint=(0.8, 0.5))
        self.form_popup.open()


    def add_contact_final_send(self, _):
        contacts = grab_contacts()
        chat_name = self.add_contact_chat_name.text
        contact_id = self.add_contact_contact_id.text
        if contact_id is None or len(contact_id.strip()) == 0:
            return
        new_contact = {"chat_name": chat_name, "contact_id": contact_id}
        contacts.append(new_contact)
        Path(storage_path/"contact_registry.json").write_text(json.dumps(contacts))

        message, _ = messages.first_message_send_init(
            contact_id, "first message",
            sender_id=base64.urlsafe_b64encode(pubkey_bytes).decode()
            )
        keys.send_to_all_servers(json.loads(message))

        if self.form_popup:
            self.form_popup.dismiss()
            self.form_popup = None

    def add_contact_final_recv(self, _):
        contacts = grab_contacts()
        chat_name = self.add_contact_chat_name.text
        contact_id = self.add_contact_contact_id.text
        if contact_id is None or len(contact_id.strip()) == 0:
            return
        new_contact = {"chat_name": chat_name, "contact_id": contact_id}
        contacts.append(new_contact)
        Path(storage_path/"contact_registry.json").write_text(json.dumps(contacts))

        raw = keys.grab_type_from_server(base64.urlsafe_b64encode(pubkey_bytes).decode(), "message")
        if raw is None or len(raw) == 0:
            popup = Popup(
                title='No message',
                content=Label(
                    text='No message yet, try sending one, or make sure that you share a server with the contact'
                    ),
                size_hint=(0.6, 0.4)
            )
            popup.open()
            return
        raw = raw[0]['_source']

        try:
            inner, _ = messages.first_message_recv_init(
                contact_id, raw, base64.urlsafe_b64encode(pubkey_bytes).decode()
                )
            if inner is None:
                if self.form_popup:
                    self.form_popup.dismiss()
                    self.form_popup = None
                return
        except ConnectionError:
            if self.form_popup:
                self.form_popup.dismiss()
                self.form_popup = None
            return
        payload_bytes = base64.urlsafe_b64decode(inner["message_bytes"])
        message = messages.decompress(payload_bytes, inner["compression_type"]).decode()
        recv_path = Path(storage_path/"contacts"/contact_id/"messages"/"recv")
        recv_path.mkdir(parents=True, exist_ok=True)
        Path(recv_path/f'{raw["uuid"]}.json').write_text(json.dumps(inner))
        print(message)

        if self.form_popup:
            self.form_popup.dismiss()
            self.form_popup = None









class edit_serverlist_popup(BoxLayout):

    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', padding=20, spacing=10, **kwargs)
        self.popup = None
        self.form_popup = None


        self.serverlist_csv_path = Path('serverlist.csv')

        contents = self.serverlist_csv_path.read_text(encoding='utf-8')


        self.edit_area = TextInput(text=contents)

        self.submit_btn = Button(text="Apply", on_press=self.save_file)

        self.add_widget(self.edit_area)
        self.add_widget(self.submit_btn)





    def save_file(self, _):
        self.serverlist_csv_path.write_text(self.edit_area.text)
        if self.popup is not None:
            self.popup.dismiss()


    def open(self):
        self.popup = Popup(title='serverlist.csv', content=self)
        self.popup.open()













class home_screen(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', padding=20, spacing=10, **kwargs)

        contact_id_label = Label(
            text='Contact id',
            font_name='RobotoMono',
            size_hint_y=0.1
        )
        contact_id_label_two: Any = Label(
            text=base64.urlsafe_b64encode(pubkey_bytes).decode(),
            font_name='RobotoMono',
            valign='top',
            halign='center',
            size_hint_y=0.2,
            size_hint_x=0.7,
            pos_hint={'center_x': 0.5},
            height=60,
        )
        contact_id_label_two.bind(
            width=lambda lbl, w: setattr(lbl, 'text_size', (w, None))
        )
        self.add_widget(contact_id_label)
        self.add_widget(contact_id_label_two)

        chats: Any = Button(text="Chats", size_hint_y=0.2)
        chats.bind(on_press=self.open_contacts)
        self.add_widget(chats)

        new_keys_btn: Any = Button(text="New keys",size_hint_y=0.2)
        new_keys_btn.bind(on_press=new_keys)
        self.add_widget(new_keys_btn)

        edit_server_list_btn: Any = Button(text="Edit serverlist.csv",size_hint_y=0.2)
        edit_server_list_btn.bind(on_press=self.open_edit_server_list)
        self.add_widget(edit_server_list_btn)




    def open_contacts(self, instance):
        chooser = choose_contact_popup()
        chooser.open()

    def open_edit_server_list(self, instance):
        edit = edit_serverlist_popup()
        edit.open()





class WBMS(App):

    def build(self):
        return home_screen()





if __name__ == '__main__':
    WBMS().run()
