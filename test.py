from Authenticator import *

if __name__ == "__main__":
    auth = Authen()
    otp, cd = auth.get_totp(image_file="test.png")
    #otp, cd = auth.get_totp(secret="MLR3LJBM6MWKW7Y3PQNRONJXVKURCCLJ")
    print("OTP: {}, CD: {}".format(otp, cd))
