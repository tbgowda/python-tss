#!/usr/bin/python

import sys
import binascii
import uuid
from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

'''
00000000-0000-0000-1000-000000000000 - x
00000000-0000-0000-2000-000000000000 - x
00000000-0000-0000-3000-000000000000 - x
00000000-0000-0000-4000-000000000000 - legacy
00000000-0000-0000-5000-000000000000 - legacy - works - PKCSV15
00000000-0000-0000-6000-000000000000 - legacy - x - OAEP 
00000000-0000-0000-7000-000000000000 - legacy - works - PKCSV15
00000000-0000-0000-8000-000000000000 - bind - works(only TPM bind/unbind) - PKCSV15
'''

well_known_secret = bytearray([0] * 20)
srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')
#bindKey_uuid = uuid.UUID('{00000000-0000-0000-7000-000000000000}')
bindKey_uuid = uuid.UUID('{c76054b8-e0db-41e9-8c3a-b8251b71661f}')

if __name__ == "__main__":

    context = TspiContext()
    context.connect()

    tpm = context.get_tpm_object()
    #tpmpolicy = tpm.get_policy_object(TSS_POLICY_USAGE)
    #tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    try:
	srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)
	#keypolicy = srk.get_policy_object(TSS_POLICY_USAGE)
	#keypolicy.set_secret(TSS_SECRET_MODE_NONE, well_known_secret)

	if len(sys.argv) > 1 and sys.argv[1] == 'create':
	        bindKey = context.create_rsa_key(TSS_KEY_TYPE_LEGACY|TSS_KEY_SIZE_2048)
	        #bindKey = context.create_rsa_key(TSS_KEY_TYPE_BIND|TSS_KEY_SIZE_2048)
		bindKey.set_attribute_uint32(tss_lib.TSS_TSPATTRIB_KEY_INFO, tss_lib.TSS_TSPATTRIB_KEYINFO_ENCSCHEME, tss_lib.TSS_ES_RSAESPKCSV15)
		#bindKey.set_attribute_uint32(tss_lib.TSS_TSPATTRIB_KEY_INFO, tss_lib.TSS_TSPATTRIB_KEYINFO_ENCSCHEME, tss_lib.TSS_ES_RSAESOAEP_SHA1_MGF1)

                bindKey.create_key(srk, 0)
                pubKey = bindKey.get_pubkey()

                print "========CREATE========"
                print binascii.hexlify(pubKey)

                context.register_key(bindKey, TSS_PS_TYPE_SYSTEM, bindKey_uuid, TSS_PS_TYPE_SYSTEM, srk_uuid)

        bindKey = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, bindKey_uuid)

	symKey = tpm.get_random(32)
	print binascii.hexlify(symKey)

	bindedBlob = bindKey.bind(binascii.hexlify(symKey))
	print binascii.hexlify(bindedBlob)
		
	with open('binded.data', 'w') as bindedFile:
		bindedFile.write(bindedBlob)

        bindKey = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, bindKey_uuid)
	with open('binded.data', 'r') as bindedFile:
                unbindedDataRaw = bytearray(bindedFile.read())
		unbindedData = bindKey.unbind(unbindedDataRaw)

	print unbindedData
		
    except tspi_exceptions:
        print "Error encountered"
