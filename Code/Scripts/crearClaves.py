#!/usr/bin/env python
# coding: utf-8

import context
from criptografia import *

if __name__=="__main__":

    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    

    guardarClavePublica(public_key,"../../Keys/public_key.pem")
    guardarClavePrivada(private_key,"../../Keys/private_key.pem")
