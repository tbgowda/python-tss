#!/usr/bin/python


from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

if __name__ == "__main__":

    context = TspiContext()
    context.connect()

    tpm = context.get_tpm_object()

    ek = tpm.get_pub_endorsement_key()
    try:
        with open('key.bin.enc', 'r') as bindedFile:
		unbindedDataRaw = bytearray(bindedFile.read())
		unbindedData = bindKey.unbind(unbindedDataRaw)
	print unbindedData	
    except tspi_exceptions.TPM_E_DISABLED_CMD:
        print "DISABLED"      
