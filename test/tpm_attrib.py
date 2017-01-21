#!/usr/bin/python

import sys
import binascii
import uuid
from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

well_known_secret = bytearray([0] * 20)
srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')
signKey_uuid = uuid.UUID('{44667294-e1b7-46fe-9581-9acc39d6d199}')
#signKey_uuid = uuid.UUID('{30f5998d-c218-4a46-bc99-211f9bf10019}')

if __name__ == "__main__":

    context = TspiContext()
    context.connect()

    try:
	srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)

	signKey = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, signKey_uuid)
	pubKey = signKey.get_pubkey()

	#attr = signKey.get_attribute_data(TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_SIZE)
	#attr = signKey.get_attribute_data(TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY)
	attr = signKey.get_attribute_uint32(TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_USAGE)
	print attr
	print TSS_KEYUSAGE_SIGN
	'''
	print TSS_KEY_TYPE_IDENTITY
	print TSS_KEY_TYPE_LEGACY
	print TSS_KEY_TYPE_SIGNING
	'''

	print "========READ========"
	print binascii.hexlify(pubKey)

    except tspi_exceptions:
        print "Error encountered"
