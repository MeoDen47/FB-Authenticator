import hmac
import base64
import struct
import hashlib
import time
import re
from pyzbar.pyzbar import decode
from PIL import Image

class Authen:

    def __init__(self):
        pass

    def __get_hotp_token(self, secret, intervals_no):
        key = base64.b32decode(secret, True)
        msg = struct.pack(">Q", intervals_no)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = h[19] & 15
        h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
        cd = 30 - (int(time.time()) - (intervals_no * 30))
        return h, cd

    def __get_totp_token(self, secret):
        return self.__get_hotp_token(secret, intervals_no=int(time.time())//30)

    def __decode_qr_fb(self, image_file, fb_regex):
        result = decode(Image.open(image_file))[0]
        data = str(result.data)
        if fb_regex == r"":
            fb_regex = r".+totp\/(.+)\?secret=(.+)&digits=(\d+)&issuer=(.+)"
        data = re.search(fb_regex, data)
        output = dict()
        output["status"] = False
        if data:
            output["status"] = True
            output["user"] = data.group(1)
            output["secret"] = data.group(2)
            output["digit"] = data.group(3)
            output["issuer"] = data.group(4)
        return output

    def get_totp(self, image_file="", secret="", fb_regex=r""):
        otp = cd = None
        if secret != "":
            otp, cd = self.__get_totp_token(secret)
        elif image_file != "":
            qrcode = self.__decode_qr_fb(image_file, fb_regex)
            if qrcode["status"]:
                secret = qrcode["secret"]
                otp, cd = self.__get_totp_token(secret)
        return otp, cd