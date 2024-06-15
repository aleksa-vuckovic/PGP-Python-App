
#pgp sending message frame variables
# variables
authentication_flag=None
authentication_private_key_id=None

encryption_flag=None
encryption_public_key_id=None
encryption_alorithm_var=None

zip_flag=None

radix_flag=None

passphrase_password=None

from keys import *
from pprint import  pprint
pprint(PublicKeyRing.get_instance().get_all())

import base64

msg="milan"
msg=str(msg).encode('ascii')
print("prvo:",msg)
msg=base64.b64encode(str(msg).encode('ascii'))
print("drugo:",msg)
msg=msg.decode('ascii')
print("trece:",msg)
print("65".decode("ascii"))

