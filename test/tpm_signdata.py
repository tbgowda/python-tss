#!/usr/bin/python

import sys
import uuid
import binascii
from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

well_known_secret = bytearray([0] * 20)
srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')
signKey_uuid = uuid.UUID('{00000000-0000-0000-0000-000000001000}')
signSecondKey_uuid = uuid.UUID('{00000000-0000-0000-0000-000000002000}') # This should be created in tpm_createkey.py

if __name__ == "__main__":

    try:
	context = TspiContext()
	context.connect()

	tpm = context.get_tpm_object()
	tpmpolicy = tpm.get_policy_object(TSS_POLICY_USAGE)
	tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

	srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)
	keypolicy = srk.get_policy_object(TSS_POLICY_USAGE)
	keypolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

	signKey = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, signKey_uuid)
	signSecondKey = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, signSecondKey_uuid)

	pubKey = signKey.get_pubkey()
	pubKeyExponent = signKey.get_pubkey_exponent()

	print "========SIGN KEY========"
	print "MODULUS: " + binascii.hexlify(pubKey)

	print "EXPONENT: " + binascii.hexlify(pubKeyExponent)

	print "=======HASH SIGN========"
	hashData = "My sacrifice"
	hash = context.create_hash(TSS_HASH_SHA1)

	hash.update(hashData)
	digest = hash.get_digest()
	print "DIGEST: " + binascii.hexlify(digest)

	signature = hash.sign(signKey)
	print "SIGNED DIGEST: " + binascii.hexlify(signature)

	hash.verify(signKey, signature)

	'''
	print "========Second key========="
	print "MODULUS: " + binascii.hexlify(signSecondKey.get_pubkey())
	print "EXPONENT: " + binascii.hexlify(signSecondKey.get_pubkey_exponent())
	hash.verify(signSecondKey, signature)
	'''

    except tspi_exceptions:
        print "Error encountered"
