#!/usr/bin/env python
# coding: utf-8

# Encriptado de imsis
# Librerias
# En primer lugar, importamos las librerias necesarias.

import numpy as np #Libreria matemática

# Generación de imsi aleatorio
# Ahora vamos a generar un imsi aleatorio. Para eso veamos la estructura del imsi. Son 3 digitos del MCC (Código del operador), luego 2 o 3 dígitos del MNC (Código del pais) y luego 10 digitos del MSIN (que es la parte que nos identifica como usuarios
# Para que sea facil crear IMSIs, creamos una función.

def generarIMSI():
    listadigitos = np.random.randint(0,10,size=(15,1)).flatten()
    IMSI = []
    for i in listadigitos:
        IMSI.append(str(i))
    IMSI = "".join(IMSI)
    return IMSI


# Procesado del IMSI
# Para procesar el IMSI, vamos a aplicarle un hash a este (que es una función inyectiva. Esto lo vamos a hacer después de sacar el código del Pais y del Operador.

def procesarIMSI(imsi,funcionhash):
    procesado = {}
    procesado["MCC"] = imsi[:3] #El MCC son los 3 primeros dígitos
    procesado["MNC"] = imsi[3:5]
    procesado["Hash"] = funcionhash(imsi.encode("ASCII")).hexdigest() #Creamos un hash con sha3_256 que es muy seguro
    return procesado