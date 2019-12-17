#!/usr/bin/env python
# coding: utf-8

# Encriptado de imsis
# Librerias
# En primer lugar, importamos las librerias necesarias.

import numpy as np #Libreria matemática
import hashlib #libreria de hashes
import json #Libreria para dumpear diccionarios
import time #Libreria para calcular cuanto le cuesta hacer las cosas
import socket #Para la conexión con el servidor
import argparse #Libreria para parsear los argumentos
import context #Importamos el contexto de nuestras librerias
from procesarImsi import *
from criptografia import *

MAXDICTSFORCON = 100000

# Envio del dato encriptado
# Vamos a crear una función que envie a través de un socket los datos encriptados. Para eso vamos a establecer un pequeño protocolo:
#     - Para comenzar la conexión pondremos START CONECTION. El servidor contestará CONECTION STARTED o ERROR.
#     - Para enviar un diccionario de imsi encriptado pondremos IMSI diccionario. El servidor contestará OK o ERROR.
#     - Para cerrar la conexión enviaremos STOP CONECTION. El servidor no contestará.



class ComunicationError(ValueError):
    def __init__(self, message, *args):         
        super(ComunicationError, self).__init__(message, *args)


def enviarIMSIs(listaDeDiccionarios,HOST,PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as mi_socket:
        tupla = (HOST, int(PORT))
        
        #Defino el protocolo
        protocolo = {}
        protocolo["INICIO_SEND"] = "START CONECTION"
        protocolo["INICIO_RECEIVE"] = "CONECTION STARTED"
        protocolo["IMSI_SEND"] = "IMSI "
        protocolo["IMSI_RECEIVE"] = "OK"
        protocolo["IMSI_ERROR"] = "IMSI ERROR"
        protocolo["FIN_SEND"] = "STOP CONECTION"
        
        mi_socket.connect(tupla)
        mi_socket.sendall(bytes(protocolo["INICIO_SEND"], encoding='utf8'))
        
        dato_recibido_en_bytes = mi_socket.recv(1024)
        dato_recibido_en_str = dato_recibido_en_bytes.decode("utf-8")
        if dato_recibido_en_str[:len(protocolo["INICIO_RECEIVE"])] == protocolo["INICIO_RECEIVE"]:
            if verbose>0:
                print("Comunicación iniciada")
        else:
            raise ComunicationError("Ha habido un error al iniciar la comunicación con el protocolo.")
        j = 0
        while j<len(listaDeDiccionarios):
            i = listaDeDiccionarios[j]
            mi_socket.sendall(bytes(protocolo["IMSI_SEND"], encoding='utf8'))
            mi_socket.sendall(i)
            dato_recibido_en_bytes = mi_socket.recv(1024)
            dato_recibido_en_str = dato_recibido_en_bytes.decode("utf-8")
            if dato_recibido_en_str[:len(protocolo["IMSI_RECEIVE"])] == protocolo["IMSI_RECEIVE"]:
                if verbose>1:
                    print("Diccionario enviado")
                j+=1
            elif dato_recibido_en_str[:len(protocolo["IMSI_ERROR"])] == protocolo["IMSI_ERROR"]:
                if verbose>0:
                    print("Error en un diccionario.")
                    print(i)
                j+=1
            else:
                raise ComunicationError("Ha habido un error al enviar un diccionario.")
        mi_socket.sendall(bytes(protocolo["FIN_SEND"], encoding='utf8'))
        time.sleep(1)

def convertirFecha(fecha):
	'''
	Convierte Dec 12, 2018 22:10:55.101962908 CET
	en 2018-12-12T22:10:55.101Z
	'''

	fechaSeparada = fecha.split(' ')
	corregidor=0
	if fechaSeparada[1]=='':
		corregidor=1
	
	fechaEnBuenFormato = fechaSeparada[2+corregidor]+"-"
	if fechaSeparada[0]=='Dec':
		fechaEnBuenFormato += "12-"
	elif fechaSeparada[0]=='Nov':
		fechaEnBuenFormato += "11-"
	elif fechaSeparada[0]=='Oct':
		fechaEnBuenFormato += "10-"
	elif fechaSeparada[0]=='Sep':
		fechaEnBuenFormato += "09-"
	elif fechaSeparada[0]=='Aug':
		fechaEnBuenFormato += "08-"
	elif fechaSeparada[0]=="Jul":
		fechaEnBuenFormato += "07-"
	elif fechaSeparada[0]=='Jun':
		fechaEnBuenFormato += "06-"
	elif fechaSeparada[0]=='May':
		fechaEnBuenFormato += "05-"
	elif fechaSeparada[0]=='Apr':
		fechaEnBuenFormato += "04-"
	elif fechaSeparada[0]=='Mar':
		fechaEnBuenFormato += "03-"
	elif fechaSeparada[0]=='Feb':
		fechaEnBuenFormato += "02-"
	elif fechaSeparada[0]=='Jan':
		fechaEnBuenFormato += "01-"
	else:
		fechaEnBuenFormato += "?-"
	if corregidor==1:
		fechaEnBuenFormato+="0"
	fechaEnBuenFormato= fechaEnBuenFormato + fechaSeparada[1+corregidor][:-1] + "T"
	fechaEnBuenFormato= fechaEnBuenFormato + fechaSeparada[3+corregidor][0:12] + "Z"

	return fechaEnBuenFormato

def leerFicheroImsi(filename):
    with open(filename,"r+") as archivo:
        fechas = []
        pwr = []
        gsmtapantenna = []
        imsi = []

        for i in archivo:
            linea = i.split("\t")
            if (len(linea)>3) and (linea[3]!='\n'):
                fechas.append(convertirFecha(linea[0]))
                pwr.append(linea[1])
                gsmtapantenna.append(linea[2])
                miImsi = linea[3].split(",")
                miImsi = miImsi[0].split("\n")
                miImsi = miImsi[0]
                imsi.append(miImsi)
    return imsi,gsmtapantenna,pwr,fechas

def parsearArgumentos():
    parser = argparse.ArgumentParser(description='Programa para enviar.')
    parser.add_argument('-r','--random', required=False, type=int, help="Genera tantos imsis aleatorios como numeros se pongan despues.")
    parser.add_argument('-f','--file', required=False, help="Archivo de donde sacar los imsis si no se generan aleatoriamente")
    parser.add_argument('-o','--host', required=True, help="Host al que se le envian los datos.")
    parser.add_argument('-p','--port', required=True, help="Puerto del host al que se le envian los datos.")
    parser.add_argument('-a','--hash', required=False, default="sha3_256", help="Hash que se usa para hashear el imsi.")
    parser.add_argument('-v','--verbose',required=False, type=int, default=0, help="Cosas que se muestran por pantalla")
    args = parser.parse_args()
    return args

def parsearFuncionHash(nombre):
    switcher ={
        "sha1" : hashlib.sha1,
        "sha224" : hashlib.sha224,
        "sha256" : hashlib.sha256,
        "sha384" : hashlib.sha384,
        "sha512" : hashlib.sha512,
        "blake2b" : hashlib.blake2b,
        "blake2s" : hashlib.blake2s,
        "md5" : hashlib.md5,
        "sha3_224" : hashlib.sha3_224,
        "sha3_256" : hashlib.sha3_256,
        "sha3_384" : hashlib.sha3_384,
        "sha3_512" : hashlib.sha3_512
    }
    # Get the function from switcher dictionary
    func = switcher.get(nombre, lambda: "Invalid hash")
    # Execute the function
    return func
    
# Programa principal

if __name__ == "__main__":

    args = parsearArgumentos()
    random = args.random
    filename = args.file
    hashfunc = parsearFuncionHash(args.hash)
    verbose = args.verbose
    
    file2 = open(args.hash+".csv","w+")
    file2.write("Nº Prueba;Tiempo medio procesar;Varianza tiempo procesar;Tiempo medio encriptar;Varianza tiempo encriptar;Tiempo envio;Tiempo total;\n")
    for i in range(100):
        print(i)
        file2.write(str(i+1)+";")
        tiempoinicial = time.time()
        if (random != None) and (filename != None):
            print("No puedes decir que se generen imsis aleatorios y nombres de archivos simultaneamente. Es contradictorio.")
            exit(-1)

        if (filename == None) and (random == None):
            print("Tienes que definir alguno de los parametros")
            exit(-1)

        public_key = leerClavePublica("../../Keys/public_key.pem")
        listaaenviar = []
        tiempoprocesar = []
        tiempoencriptar = []
        if random != None:
            for i in range(random):
                imsi = generarIMSI()

                tiempoantes = time.time()
                procesado = procesarIMSI(imsi,hashfunc)

                del imsi #Borramos la variable imsi despues de procesarla

                tiempoahora = time.time()
                tiempoprocesar.append(tiempoahora-tiempoantes)
                if verbose > 1:
                    print("El tiempo en procesar el imsi "+str(i)+" ha sido %.50f segundos" % (tiempoahora-tiempoantes))

                tiempoantes = time.time()
                encriptada = encriptar(public_key,json.dumps(procesado))
                tiempoahora = time.time()
                tiempoencriptar.append(tiempoahora-tiempoantes)
                if verbose > 1:
                    print("El tiempo en encriptar el imsi "+str(i)+" ha sido %.20f segundos" % (tiempoahora-tiempoantes))

                listaaenviar.append(encriptada)

            if verbose > 0:
                print("El tiempo en procesar de media ha sido %.50f segundos" % np.mean(tiempoprocesar))
                file2.write("%.50f;"% np.mean(tiempoprocesar))
                print("La varianza del tiempo en procesar ha sido %.50f segundos" % np.var(tiempoprocesar))
                file2.write("%.50f;"% np.var(tiempoprocesar))
                print("El tiempo en encriptar de media ha sido %.20f segundos" % np.mean(tiempoencriptar))
                file2.write("%.50f;"% np.mean(tiempoencriptar))
                print("La varianza del tiempo en encriptar ha sido %.20f segundos" % np.var(tiempoencriptar))
                file2.write("%.50f;"% np.var(tiempoencriptar))
                
        

        if filename != None:
            imsi,gsmtapantenna,pwr,fechas = leerFicheroImsi(filename)
            for i in range(len(imsi)):

                tiempoantes = time.time()
                procesado = procesarIMSI(imsi[i],hashfunc)
                tiempoahora = time.time()
                tiempoprocesar.append(tiempoahora-tiempoantes)
                if verbose > 1:
                    print("El tiempo en procesar el imsi "+str(i)+" ha sido %.50f segundos" % (tiempoahora-tiempoantes))

                procesado["gsmtapantenna"]=gsmtapantenna[i]
                procesado["pwr"]=pwr[i]
                procesado["fechas"]=fechas[i]

                tiempoantes = time.time()
                encriptada = encriptar(public_key,json.dumps(procesado))
                tiempoahora = time.time()
                tiempoencriptar.append(tiempoahora-tiempoantes)
                if verbose > 1:
                    print("El tiempo en encriptar el imsi "+str(i)+" ha sido %.20f segundos" % (tiempoahora-tiempoantes))

                listaaenviar.append(encriptada)

            if verbose > 0:
                print("El tiempo en procesar de media ha sido %.50f segundos" % np.mean(tiempoprocesar))
                print("La varianza del tiempo en procesar ha sido %.50f segundos" % np.var(tiempoprocesar))
                print("El tiempo en encriptar de media ha sido %.20f segundos" % np.mean(tiempoencriptar))
                print("La varianza del tiempo en encriptar ha sido %.20f segundos" % np.var(tiempoencriptar))


        if (random != None) or (filename != None):
            tiempoantes = time.time()
            for i in range(0,len(listaaenviar),MAXDICTSFORCON):
                if len(listaaenviar)<(i+MAXDICTSFORCON):
                    enviarIMSIs(listaaenviar[i:],args.host,args.port)
                else:
                    enviarIMSIs(listaaenviar[i:(i+MAXDICTSFORCON)],args.host,args.port)
            tiempoahora = time.time()
            if verbose > 0:
                print("El tiempo en enviar los datos ha sido %.20f segundos" % (tiempoahora-tiempoantes))
                file2.write("%.50f;"% (tiempoahora-tiempoantes))

        tiempofinal = time.time()
        if (verbose > 0):
            print("El tiempo total ha sido %.20f segundos" % (tiempofinal-tiempoinicial))
            file2.write("%.50f;\n"% (tiempofinal-tiempoinicial))

    file2.close()


