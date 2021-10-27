#!/bin/sh

apk add curl jq

# TODO while ethconnect is not ready, wait...

ADDITIONAL_HEADERS=""
if [ "${ETHCONNECT_USERNAME+1}" && "${ETHCONNECT_PASSWORD+1}"  ]
then
  BASIC_AUTH=`echo -n "${ETHCONNECT_USERNAME}:${ETHCONNECT_PASSWORD} | base64"`
  ADDITIONAL_HEADERS="-H 'Authorization: Basic ${BASIC_AUTH}'"
fi

# TODO only deploy contract if it hasn't already been deployed, i.e. make it more idempotent

HTTP_CODE=`curl \
  --output /tmp/contract_deploy.json --write-out "%{http_code}" ${ADDITIONAL_HEADERS} \
  -X POST -H 'Content-Type: application/json' -d '{}' \
  "https://${ETHCONNECT_URL}${FF_CONTRACT_GATEWAY_ENDPOINT}/?${ETHCONNECT_PREFIX}-from=${FF_ORG_ADDRESS}&${ETHCONNECT_PREFIX}-sync=true"`

if [ "$HTTP_CODE" -ne 200 ]; then
  echo "Failed to deploy contract with code ${HTTP_CODE}"
  exit 1
fi

FF_CONTRACT_ADDRESS=`cat /tmp/contract_deploy.json | jq -r '.contractAddress'`
echo "Deployed FireFly smart contract to address ${FF_CONTRACT_ADDRESS}"
