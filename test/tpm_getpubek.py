#!/usr/bin/python

import binascii
from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

well_known_secret = bytearray([0] * 20)

if __name__ == "__main__":

    context = TspiContext()
    context.connect()

    tpm = context.get_tpm_object()
    tpmpolicy = tpm.get_policy_object(TSS_POLICY_USAGE)
    tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    try:
        ek = tpm.get_pub_endorsement_key()
        pubEk = ek.get_pubkey()
        print binascii.hexlify(pubEk)
    except tspi_exceptions:
        print "Error encountered"
