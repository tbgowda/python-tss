#!/usr/bin/python


from pytss import *
from pytss.tspi_exceptions import *
from pytss.tspi_defines import *

well_known_secret = bytearray([0] * 20)

if __name__ == "__main__":

    context = TspiContext()
    context.connect()

    tpm = context.get_tpm_object()
    tpmpolicy = tpm.get_policy_object(TSS_POLICY_USAGE)
    tpmpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    srk = context.create_rsa_key(TSS_KEY_TSP_SRK | TSS_KEY_AUTHORIZATION)
    srkpolicy = srk.get_policy_object(TSS_POLICY_USAGE)
    srkpolicy.set_secret(TSS_SECRET_MODE_SHA1, well_known_secret)

    try:
        tpm.take_ownership(srk)
    except tspi_exceptions.TPM_E_DISABLED_CMD:
        print "DISABLED"      
