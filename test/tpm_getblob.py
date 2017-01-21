#!/usr/bin/python

import sys
import binascii
import uuid
from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

well_known_secret = bytearray([0] * 20)
srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')
signKey_uuid = uuid.UUID('{60ac85dc-2bf9-4803-b761-f819a14d7486}')

if __name__ == "__main__":

    context = TspiContext()
    context.connect()

    tpm = context.get_tpm_object()

    try:
	srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)

	signKey = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, signKey_uuid)
	pubBlob = signKey.get_keyblob()

	print "========READ========"
	print binascii.hexlify(pubBlob)

	with open('a.blob', 'w') as f:
	    f.write(pubBlob)

    except tspi_exceptions:
        print "Error encountered"
