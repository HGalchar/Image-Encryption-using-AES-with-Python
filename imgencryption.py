from Crypto.Cipher import AES
from Crypto import Random
import base64
from PIL import Image

img='pic.jpg'

key = Random.new().read(AES.block_size)
iv = Random.new().read(AES.block_size)

#Encryption.................

def encryption():
    print("Encryption Start.........")
    try:
        input_file = open('./imgs/img1.jpg','rb')
        input_data = input_file.read()
        b64 = base64.b64encode(input_data)
        print(b64)
        input_file.close()

        cfb_cipher = AES.new(key, AES.MODE_CFB, iv)
        enc_data = cfb_cipher.encrypt(b64)
        print(enc_data)

        enc_file = open("./Output imgs/encrypted.enc", "wb")
        enc_file.write(enc_data)
        enc_file.close()

    except Exception:
        print('Error caught : ', Exception.__name__)


#Decryption.....................

def decryption():
    print("\nDecryption Strat......")
    try:
        enc_file2 = open("./Output imgs/encrypted.enc",'rb')
        enc_data2 = enc_file2.read()
        enc_file2.close()

        cfb_decipher = AES.new(key, AES.MODE_CFB, iv)
        plain_data = cfb_decipher.decrypt(enc_data2)

        decode_b64 = base64.b64decode(plain_data)
        out_file = open('./Output imgs/op.jpg', 'wb')
        out_file.write(decode_b64)
        out_file.close()
        print("\nDecryption Done.")

    except Exception:
        print('Error caught : ', Exception.__name__)

encryption()
decryption()

im=Image.open('./Output imgs/op.jpg')
im.show()



# decode_b64 = base64.b64decode(b64)
# out_file = open('/tmp/out_newgalax.png', 'wb')
# out_file.write(decode_b64)