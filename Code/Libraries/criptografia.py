#!/usr/bin/env python
# coding: utf-8

# Encriptado de imsis
# Librerias
# En primer lugar, importamos las librerias necesarias.

# Las librerias de abajo son las librerias para encriptar el mensaje antes de mandarlo
import cryptography as crypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# Encriptado del mensaje enviado
# Ahora vamos a encriptar el mensaje que se manda al servidor. Para eso vamos a generar en primer lugar una clave pública y una clave privada.
"""
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()
"""

# Vamos a necesitar la clave privada en el servidor así que hacemos una función para guardar la clave y otra para leerla.

def guardarClavePrivada(private_key,nombrearchivo):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(nombrearchivo, 'wb') as f:
        f.write(pem)

def leerClavePrivada(nombrearchivo):
    with open(nombrearchivo, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


# Ahora hacemos lo mismo con las claves públicas, ya que necesitamos la clave pública asociada a la clave privada.

def guardarClavePublica(public_key,nombrearchivo):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(nombrearchivo, 'wb') as f:
        f.write(pem)



def leerClavePublica(nombrearchivo):
    with open(nombrearchivo, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key


# A continuación, probamos a guardar y a leer las claves publicas y privadas. Primero, guardamos las claves.

"""
guardarClavePublica(public_key,"public_key.pem")
guardarClavePrivada(private_key,"private_key.pem")
"""

# Ahora, leemos las claves de los archivos que hemos guardado.


"""
public_key = leerClavePublica("public_key.pem")
private_key = leerClavePrivada("private_key.pem")
"""


# Ahora creamos una función para encriptar y otra para desencriptar.

def encriptar(public_key,message):
    encrypted = public_key.encrypt(
        message.encode("ASCII"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def desencriptar(private_key,encrypted):
    message = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return message.decode("ASCII")