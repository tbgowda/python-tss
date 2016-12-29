#!/usr/bin/python

import binascii
from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

if __name__ == "__main__":

    context = TspiContext()
    context.connect()

    tpm = context.get_tpm_object()

    try:
        pcrValue = tpm.get_pcr(0)
        #print pcrValue[0].decode("utf-8") 
        print binascii.hexlify(pcrValue)
        pcrValue = tpm.get_pcr(1)
        #print pcrValue[0].decode("utf-8") 
        print binascii.hexlify(pcrValue)
        pcrValue = tpm.get_pcr(2)
        #print pcrValue[0].decode("utf-8") 
        print binascii.hexlify(pcrValue)
        pcrValue = tpm.get_pcr(3)
        #print pcrValue[0].decode("utf-8") 
        print binascii.hexlify(pcrValue)
        pcrValue = tpm.get_pcr(4)
        #print pcrValue[0].decode("utf-8") 
        print binascii.hexlify(pcrValue)
        pcrValue = tpm.get_pcr(5)
        #print pcrValue[0].decode("utf-8") 
        print binascii.hexlify(pcrValue)
        pcrValue = tpm.get_pcr(6)
        #print pcrValue[0].decode("utf-8") 
        print binascii.hexlify(pcrValue)
        pcrValue = tpm.get_pcr(7)
        #print pcrValue[0].decode("utf-8") 
        print binascii.hexlify(pcrValue)
        pcrValue = tpm.get_pcr(8)
        #print pcrValue[0].decode("utf-8") 
        print binascii.hexlify(pcrValue)
        pcrValue = tpm.get_pcr(9)
        #print pcrValue[0].decode("utf-8") 
        print binascii.hexlify(pcrValue)
    except tspi_exceptions:
        print "Error encountered"
