#!/usr/bin/python

import sys
import binascii
import uuid
from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

'''
KEYS created:
00000000-0000-0000-0000-000000001000
00000000-0000-0000-0000-000000002000 - not yet
00000000-0000-0000-0000-000000003000 - not yet
00000000-0000-0000-0000-000000004000 - not yet
'''

well_known_secret = bytearray([0] * 20)
srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')
signKey_uuid = uuid.UUID('{00000000-0000-0000-0000-000000001000}')

if __name__ == "__main__":

    context = TspiContext()
    #context.connect('10.10.10.1')
    context.connect()

    tpm = context.get_tpm_object()
    tpmpolicy = tpm.get_policy_object(TSS_POLICY_USAGE)
    tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    try:
	srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)
	keypolicy = srk.get_policy_object(TSS_POLICY_USAGE)
        keypolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

        if len(sys.argv) > 1 and sys.argv[1] == 'create':
		signKey = context.create_rsa_key(TSS_KEY_TYPE_SIGNING|TSS_KEY_SIZE_2048)

		signKey.create_key(srk, 0)
		pubKey = signKey.get_pubkey()

		print "========CREATE========"
		print binascii.hexlify(pubKey)

		context.register_key(signKey, TSS_PS_TYPE_SYSTEM, signKey_uuid, TSS_PS_TYPE_SYSTEM, srk_uuid)
	
	signKey = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, signKey_uuid)
	pubKey = signKey.get_pubkey()

	print "========READ========"
	print binascii.hexlify(pubKey)
	#from pyasn1.codec.der import decoder as der_decoder
	#print der_decoder.decode(pubKey)

    except tspi_exceptions:
        print "Error encountered"
