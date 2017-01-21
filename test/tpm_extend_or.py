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
        pcrValue = tpm.get_pcr(14)
        print binascii.hexlify(pcrValue)

	data = 'hello'
        m = hashlib.sha1()
        m.update('hello')
        md = m.digest()

        cdata = ffi.new('BYTE []', len(md))

	if isinstance(md, basestring):
            md = bytearray(md)

	cdata = md

	print 'SHA1 of hello'
        print binascii.hexlify(cdata)

	orvalue = pcrValue + cdata
	print binascii.hexlify(orvalue)

        m = hashlib.sha1()
        m.update(orvalue)
        md = m.digest()
        print binascii.hexlify(md)


    except tspi_exceptions:
        print "Error encountered"
