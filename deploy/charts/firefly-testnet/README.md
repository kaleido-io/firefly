
```
kind create cluster

kubectl create ns cert-manager || true
kubectl create ns firefly-testnet || true
kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.4.0/cert-manager.crds.yaml
helm repo add jetstack https://charts.jetstack.io || true

helm dep up firefly-testnet

helm upgade --install --skip-crds firefly-testnet --namespace firefly-testnet firefly-testnet ./firefly-testnet
```