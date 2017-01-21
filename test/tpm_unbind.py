#!/usr/bin/python

import sys
import binascii
import uuid
from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')
bindKey_uuid = uuid.UUID('{00000000-0000-0000-7000-000000000000}')

if __name__ == "__main__":

    context = TspiContext()
    context.connect()

    tpm = context.get_tpm_object()

    try:
	srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)
        #keypolicy = srk.get_policy_object(TSS_POLICY_USAGE)
        #keypolicy.set_secret(TSS_SECRET_MODE_NONE, well_known_secret)

        bindKey = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, bindKey_uuid)

	with open('key.bin.enc', 'r') as bindedFile:
                unbindedDataRaw = bytearray(bindedFile.read())
		unbindedData = bindKey.unbind(unbindedDataRaw)

	print unbindedData
		
    except tspi_exceptions:
        print "Error encountered"
