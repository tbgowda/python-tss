#!/usr/bin/python

import sys
import binascii
import uuid
from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')
signKey_uuid = uuid.UUID('{44667294-e1b7-46fe-9581-9acc39d6d199}')

if __name__ == "__main__":

    context = TspiContext()
    context.connect()

    try:
	srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)

        if len(sys.argv) > 1 and sys.argv[1] == 'create':
		signKey = context.create_rsa_key(TSS_KEY_TYPE_SIGNING|TSS_KEY_SIZE_2048)

		signKey.create_key(srk, 0)
		pubKey = signKey.get_pubkey()

		print "========CREATE========"
		print binascii.hexlify(pubKey)

		context.register_key(signKey, TSS_PS_TYPE_SYSTEM, signKey_uuid, TSS_PS_TYPE_SYSTEM, srk_uuid)
	
	try:
	    signKey = context.get_key_by_uuid(TSS_PS_TYPE_SYSTEM, signKey_uuid)
	    print 'Get key successful'
	except tspi_exceptions.TSS_E_PS_KEY_NOTFOUND:
	    print 'Get key failed'
	    sys.exit(0)

	pubKey = signKey.get_pubkey()

	print "========READ========"
	print binascii.hexlify(pubKey)

    except tspi_exceptions:
        print "Error encountered"
