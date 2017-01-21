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
        ek = tpm.get_pub_endorsement_key()
        pubEk = ek.get_pubkey()
        print binascii.hexlify(pubEk)
    except tspi_exceptions:
        print "Error encountered"
