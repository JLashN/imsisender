#!/usr/bin/env python
# coding: utf-8

# Servidor
# <p>Esta parte se va a ejecutar en el servidor y va a recibir los imsis cifrados.</p>

import numpy as np #Libreria matemática
import hashlib #libreria de hashes
import json #Libreria para dumpear diccionarios
import time #Libreria para calcular cuanto le cuesta hacer las cosas
import socketserver #Para la conexión con el cliente
from pymongo import MongoClient #para la conexion con mongodb
import argparse
import context
from criptografia import *

# Clase servidor
# Aqui vamos a definir la clase servidor que va a ser nuestro servidor.

class ComunicationError(ValueError):
    def __init__(self, message, *args):         
        super(ComunicationError, self).__init__(message, *args)

class MiControladorTCP(socketserver.BaseRequestHandler):
    """
    La clase que controlará las peticiones para nuestro servidor.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        """
        Método sobrescrito para controlar la comunicación que ocurra ne nuestro servidor.
        Aquí recibiremos los mensajes del cliente y le responderemos
        """
        
        #Defino el protocolo
        protocolo = {}
        protocolo["INICIO_RECEIVE"] = "START CONECTION"
        protocolo["INICIO_SEND"] = "CONECTION STARTED"
        protocolo["IMSI_RECEIVE"] = "IMSI "
        protocolo["IMSI_SEND"] = "OK"
        protocolo["IMSI_ERROR"] = "IMSI ERROR"
        protocolo["FIN_RECEIVE"] = "STOP CONECTION"
        protocolo["ERROR"] = "ERROR"
        
        dato_recibido_en_bytes = self.request.recv(1024)
        dato_recibido_en_str = dato_recibido_en_bytes.decode("utf-8")
        if dato_recibido_en_str[:len(protocolo["INICIO_RECEIVE"])] == protocolo["INICIO_RECEIVE"]:
            self.request.sendall(bytes(protocolo["INICIO_SEND"], encoding='utf8'))
            
            #Empezamos a recibir los diccionarios
            diccionarios = []
            dato_recibido_en_bytes = self.request.recv(1024)
            dato_recibido_en_str = dato_recibido_en_bytes.decode("utf-8")
            while dato_recibido_en_str[:len(protocolo["FIN_RECEIVE"])] != protocolo["FIN_RECEIVE"]:
                if dato_recibido_en_str[:len(protocolo["IMSI_RECEIVE"])] == protocolo["IMSI_RECEIVE"]:
                    try:
                        dato_recibido_en_bytes = self.request.recv(1024)
                        diccionarios.append(eval(desencriptar(private_key,dato_recibido_en_bytes)))
                        self.request.sendall(bytes(protocolo["IMSI_SEND"], encoding='utf8'))
                        dato_recibido_en_bytes = self.request.recv(1024)
                        dato_recibido_en_str = dato_recibido_en_bytes.decode("utf-8")
                    except:
                        self.request.sendall(bytes(protocolo["IMSI_ERROR"], encoding='utf8'))
                        dato_recibido_en_bytes = self.request.recv(1024)
                        dato_recibido_en_str = dato_recibido_en_bytes.decode("utf-8")
                else:
                    self.request.sendall(bytes(protocolo["ERROR"], encoding='utf8'))
                    raise ComunicationError("Hay un error en el protocolo.")

            
            #conexion con la base de datos
            client = MongoClient('mongodb://lash:tdsct5@cluster0-shard-00-00-lypsn.mongodb.net:27017,cluster0-shard-00-01-lypsn.mongodb.net:27017,cluster0-shard-00-02-lypsn.mongodb.net:27017/test?ssl=true&replicaSet=Cluster0-shard-0&authSource=admin&retryWrites=true&w=majority')
            db = client.IMSI
            posts = db.gsm
            posts.insert_many(diccionarios)
            
        else:
            self.request.sendall(bytes(protocolo["ERROR"], encoding='utf8'))
            raise ComunicationError("Hay un error en el protocolo.")            

def parsearArgumentos():
    parser = argparse.ArgumentParser(description='Programa para recibir.')
    parser.add_argument('-p','--port', default=9999, type=int, required=False, help="Puerto del host al que se le envian los datos.")
    parser.add_argument('-o','--host', default="localhost", required=False, help="Puerto del host al que se le envian los datos.")

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parsearArgumentos()
    PORT = args.port #puerto que va a estar escuchando
    HOST = args.host

    private_key = leerClavePrivada("../../Keys/private_key.pem")

    tupla_para_el_enlace = (HOST, PORT)
    try:
        with socketserver.TCPServer(tupla_para_el_enlace, MiControladorTCP) as servidor:
            servidor.serve_forever()
    except KeyboardInterrupt:
        print('Se ha detenido el servidor')
    finally:        
        if servidor is not None:
            servidor.shutdown()

