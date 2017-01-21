#!/usr/bin/python

import sys
import binascii
import uuid
from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')
sealKey_uuid = uuid.UUID('{00000000-0000-0000-0000-100000000000}')

if __name__ == "__main__":

    context = TspiContext()
    context.connect()

    tpm = context.get_tpm_object()

    try:
	srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)

	if len(sys.argv) > 1 and sys.argv[1] == 'create':
	        sealKey = context.create_rsa_key(TSS_KEY_TYPE_STORAGE|TSS_KEY_SIZE_2048)

                sealKey.create_key(srk, 0)
                pubKey = sealKey.get_pubkey()

                print "========CREATE========"
                print binascii.hexlify(pubKey)

                context.register_key(sealKey, TSS_PS_TYPE_SYSTEM, sealKey_uuid, TSS_PS_TYPE_SYSTEM, srk_uuid)

        sealKey = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, sealKey_uuid)
	keypolicy = sealKey.get_policy_object(TSS_POLICY_USAGE)
	keypolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

	symKey = tpm.get_random(32)
	print binascii.hexlify(symKey)

	sealedBlob = sealKey.seal(binascii.hexlify(symKey))
		
	with open('sealed.data', 'w') as sealedFile:
		sealedFile.write(sealedBlob)

	with open('sealed.data', 'r') as sealedFile:
                unsealedDataRaw = bytearray(sealedFile.read())
		unsealedData = sealKey.unseal(unsealedDataRaw)

	print unsealedData
		
    except tspi_exceptions:
        print "Error encountered"
