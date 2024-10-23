#!/bin/sh

DESTINATION=$1
aws s3 cp enclave/enclave.eif s3://clientimages.testnet.verida.io/marlin-enclaves/$DESTINATION