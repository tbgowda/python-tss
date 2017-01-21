#!/usr/bin/python

import binascii
from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

if __name__ == "__main__":

    context = TspiContext()
    context.connect()

    tpm = context.get_tpm_object()

    try:
        pcrValue = tpm.get_pcr(15)
	print 'Initial value of PCR'
        print binascii.hexlify(pcrValue)

	data = 'hello'
        m = hashlib.sha1()
        m.update(data)
        md = m.digest()
	print 'Hash of hello'
        print binascii.hexlify(md)

	final = pcrValue + md

	ret = tpm.extend_pcr(15, md, None)
	print 'TPM extend return value'
	print binascii.hexlify(ret)

        pcrValue = tpm.get_pcr(15)
	print 'TPM PCR value'
        print binascii.hexlify(pcrValue)

        m = hashlib.sha1()
        m.update(final)
        md = m.digest()

	print 'Hash of pcrValue + hello'
	print binascii.hexlify(md)
    except tspi_exceptions:
        print "Error encountered"
