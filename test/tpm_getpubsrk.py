#!/usr/bin/python

import binascii
import uuid
from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

well_known_secret = bytearray([0] * 20)
srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')

if __name__ == "__main__":

    context = TspiContext()
    context.connect()

    tpm = context.get_tpm_object()
    tpmpolicy = tpm.get_policy_object(TSS_POLICY_USAGE)
    tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    try:
	'''
	srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)
	keypolicy = srk.get_policy_object(TSS_POLICY_USAGE)
        keypolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)
        pubSrk = srk.get_pubkey_srk()
	print binascii.hexlify(pubSrk)
	'''
	srk, srkLen = tpm.get_pub_srk_key()
	print binascii.hexlify(srk)
	print srkLen
    except tspi_exceptions:
        print "Error encountered"
