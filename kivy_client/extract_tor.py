import re
from urllib.parse import urljoin
import shutil
import platform
import requests
import os
from pgpy import PGPKey, PGPSignature, PGPMessage

# this file is meant to run on the android version




base_url = "https://dist.torproject.org/torbrowser/"


def get_latest_tor():
    tor_versions = requests.get(base_url, timeout=20)

    urls = re.findall(r'href="([^"]+)"', tor_versions.content.decode('utf-8'))

    version_format_allowed = set("1234567890./")
    urls.sort()

    urls = [url for url in urls if set(url).issubset(version_format_allowed) and len(url) != 1]

    if len(urls) != 1:
        print('invalid number of versions detected while downloading tor')
        raise IndexError

    version_url = urls[0]

    def joinurl_inf(*args):
        """runs urljoin on each arg"""
        final_url = ""
        for arg in args:
            final_url = urljoin(final_url, arg)


        return final_url





    def get_standard_arch():
        """gets it in a way tor url expects"""
        arch = platform.machine().lower()


        mapping = {
            "amd64": "x86_64",
            "x86": "i686",
            "i386": "i686",
        }

        return mapping.get(arch, arch)




    url = joinurl_inf(base_url, version_url)+f"tor-expert-bundle-android-{get_standard_arch()}-{version_url.removesuffix("/")}"
    print(url)
    tar_file = requests.get(url+".tar.gz", timeout=10)
    sig_file = requests.get(url+".tar.gz.asc", timeout=10)
    with open('tor.tar.gz', 'wb') as f:
        f.write(tar_file.content)
    with open('tor.tar.gz.asc', 'wb') as f:
        f.write(sig_file.content)

    if not os.path.exists("tor.asc"):
        pub = requests.get("https://keys.openpgp.org/vks/v1/by-fingerprint/EF6E286DDA85EA2A4BA7DE684E2C6E8793298290", timeout=10)
        with open("tor.asc", 'wb') as f:
            f.write(pub.content)


    public_key, _ = PGPKey.from_file('tor.asc')


    signature = PGPSignature.from_file('tor.tar.gz.asc')

    message = PGPMessage.new('tor.tar.gz', file=True)


    verification = public_key.verify(message.message, signature)


    if verification:
        print("Success: The signature is valid!")
        
    else:
        print("Failure: The signature is INVALID.")
        assert True
