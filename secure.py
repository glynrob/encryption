#!/usr/bin/python 

#imports begin
import hashlib, os, fileinput
from M2Crypto import RSA
#end imports


print "Hashing\r\n";

password = 'moneky123';
saltstring = os.urandom(24)

print 'Salt = '+saltstring

md5 = hashlib.md5()
md5.update(password+saltstring)
print 'MD5 = '+md5.hexdigest()

sha1string = hashlib.sha1(password + saltstring)
print 'SHA1 = '+sha1string.hexdigest()

sha1string = hashlib.sha512(password + saltstring)
print 'SHA512 = '+sha1string.hexdigest()


print "\r\n-----------------------------------------\r\n";
print "Encryption\r\n";

secretstring = "This is the secret string I want encrypting";

print 'Secret String = '+secretstring

rsa = RSA.load_pub_key("mykey.pub")
ctxt = rsa.public_encrypt(secretstring, RSA.pkcs1_padding)
encryptedText = ctxt.encode('base64')
print 'Encrypted Text = '+encryptedText

priv = RSA.load_key("mykey.pem")
decodeEncryptedText = encryptedText.decode('base64')
decryptedText = priv.private_decrypt(decodeEncryptedText, RSA.pkcs1_padding)
print 'Decrypted Text = '+decryptedText

if decryptedText == secretstring:
    print 'DECRYPTION WORKED'
else:
    print 'DECRYPTION FAILED'
