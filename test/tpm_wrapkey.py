#!/usr/bin/python

import sys
import binascii
import uuid
from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

# NOT COMPLETE !!!

well_known_secret = bytearray([0] * 20)
srk_uuid = uuid.UUID('{00000000-0000-0000-0000-000000000001}')
signKey_uuid = uuid.UUID('{00000000-0000-0000-0000-000000001000}')

if __name__ == "__main__":

    context = TspiContext()
    context.connect()

    tpm = context.get_tpm_object()
    tpmpolicy = tpm.get_policy_object(TSS_POLICY_USAGE)
    tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    try:
	srk = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, srk_uuid)
	keypolicy = srk.get_policy_object(TSS_POLICY_USAGE)
	keypolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

	signKey = context.load_key_by_uuid(TSS_PS_TYPE_SYSTEM, signKey_uuid)
	pubKey = signKey.get_pubkey()
	pubKeyExponent = signKey.get_pubkey_exponent()

	print "========READ========"
	print "MODULUS: " + binascii.hexlify(pubKey)
	pubKeyData = binascii.hexlify(pubKey)

	print "EXPONENT: " + binascii.hexlify(pubKeyExponent)
	pubKeyData = binascii.hexlify(pubKeyExponent)

	hashData = "My sacrifice"
	hash = context.create_hash(TSS_HASH_SHA1)

	hash.update(hashData)
	digest = hash.get_digest()
	print "DIGEST: " + binascii.hexlify(digest)

	signature = hash.sign(signKey)
	print "SIGNED DIGEST: " + binascii.hexlify(signature)

        #publicKey = context.create_rsa_key(TSS_KEY_TYPE_SIGNING|TSS_KEY_SIZE_2048)
	#publicKey.set_attribute_data(TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, pubKeyData)

	#hash.verify(publicKey, binascii.hexlify(signature))

    except tspi_exceptions:
        print "Error encountered"
