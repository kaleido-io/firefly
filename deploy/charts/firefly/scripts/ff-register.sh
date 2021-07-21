#!/bin/sh

set -e

until curl --fail --silent -X GET "${FF_URL}/network/organizations"; do
  echo "Waiting for firefly to be available"
  sleep 5
done

echo "Registering organization"
curl --silent -X POST -d '{}' -H 'Content-Type: application/json' \
  "${FF_URL}/network/register/node/organization"

org_exists=$(curl --silent -X GET "${FF_URL}/network/organizations" | jq ".[] | select(.name == \"${ORG_NAME}\") | .name" 2>/dev/null | wc -l)
echo "org_exists: ${org_exists}"
until [ "$org_exists" -eq "1" ]; do
  echo "Waiting for org to finish registration"
  sleep 5
  org_exists=$(curl --silent -X GET "${FF_URL}/network/organizations" | jq ".[] | select(.name == \"${ORG_NAME}\") | .name" 2>/dev/null | wc -l)
  echo "org_exists: ${org_exists}"
done

echo "Registering node"
curl --silent -X POST -d '{}' -H 'Content-Type: application/json' \
  "${FF_URL}/network/register/node"

node_exists=$(curl --silent -X GET "${FF_URL}/network/nodes" | jq ".[] | select(.name == \"${NODE_NAME}\") | .name" 2>/dev/null | wc -l)
echo "node_exists: ${node_exists}"

until [ "$node_exists" -eq "1" ]; do
  echo "Waiting for nodes to finish registration"
  sleep 5
  node_exists=$(curl --silent -X GET "${FF_URL}/network/nodes" | jq ".[] | select(.name == \"${NODE_NAME}\") | .name" 2>/dev/null | wc -l)
  echo "node_exists: ${node_exists}"
done

echo "Registration complete"
