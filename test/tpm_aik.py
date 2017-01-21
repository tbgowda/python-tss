#!/usr/bin/python

import sys
import binascii
import uuid
from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

'''
30f5998d-c218-4a46-bc99-211f9bf10019
'''

well_known_secret = bytearray([0] * 20)
srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')
aik_uuid = uuid.UUID('{30f5998d-c218-4a46-bc99-211f9bf10019}')

if __name__ == "__main__":

    context = TspiContext()
    context.connect()

    tpm = context.get_tpm_object()

    try:
	srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)

	n = bytearray([0xff] * (2048/8))
    	pcakey = context.create_rsa_key(TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048)
    	pcakey.set_modulus(n)

    	aik = context.create_rsa_key(TSS_KEY_TYPE_IDENTITY|TSS_KEY_SIZE_2048)

    	data = tpm.collate_identity_request(srk, pcakey, aik)

	pubkey = aik.get_pubkeyblob()
    	blob = aik.get_keyblob()
	context.register_key(aik, TSS_PS_TYPE_SYSTEM, aik_uuid, TSS_PS_TYPE_SYSTEM, srk_uuid)

    except tspi_exceptions:
        print "Error encountered"
