#!/usr/bin/python

import binascii
import uuid
from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')

if __name__ == "__main__":

    context = TspiContext()
    context.connect()

    tpm = context.get_tpm_object()

    try:
	srk, srkLen = tpm.get_pub_srk_key()
	print binascii.hexlify(srk)
	print srkLen
    except tspi_exceptions:
        print "Error encountered"
