#!/bin/bash
set -euo pipefail

THIS_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
VERAISON=${THIS_DIR}/../services/deployments/docker/veraison

source ${THIS_DIR}/../services/deployments/docker/env.bash

build_endorsements() {
    ${VERAISON} -- cocli comid create \
        --template ${THIS_DIR}/data/comid-psa-ta.json \
        --template ${THIS_DIR}/data/comid-psa-refval.json \
        --output-dir ${THIS_DIR}/data
    ${VERAISON} -- cocli corim create \
        --template ${THIS_DIR}/data/corim-psa.json \
        --comid ${THIS_DIR}/data/comid-psa-refval.cbor \
        --comid ${THIS_DIR}/data/comid-psa-ta.cbor \
        --output ${THIS_DIR}/data/psa-endorsements.cbor
}

submit_endorsements() {
    $VERAISON -- cocli corim submit \
        --corim-file ${THIS_DIR}/data/psa-endorsements.cbor \
        --media-type "application/corim-unsigned+cbor; profile=\"http://arm.com/psa/iot/1\""
}

build_endorsements
submit_endorsements
