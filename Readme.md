# Verida API server

This repo contains the code to build enclave image to run verida API server. It uses a self signed certificate and enables HTTPS connection to the API server. The TLS session ends within the enclave so that data is secured end to end. 

## Pre requisites

To run the API server within enclave following pre requisites are necessary

1. Docker
2. A metamask account on Arbitrum one with some ETH(for gas) and some USDC(to pay for oyster enclave)

## Generate SSH keys

```sh
cd secretMgmt
cargo run --bin keygen -- --secret data/key.sec --public data/key.pub
```


## Build enclave

Enclave can be built by running the following command

```sh
docker build -t enclave .
docker run -it --privileged -v `pwd`:/app/mount enclave
```

This creates a folder named `enclave` which will contain the enclave image file named `enclave.eif`. Please use this image to deploy the enclave.

Note: Current repo assumes the build machine as well as enclave is arm64. If amd64 is used for building enclave, please replace all instances of arm64 to amd64 and use amd64 while deploying the enclave.

# Deploy enclave

To deploy the enclave please follow the guide in docs [here](https://docs.marlin.org/user-guides/oyster/instances/tutorials/nodejs-server/deploy).

## Update DNS

Update A record of the DNS with the IP address.

There will be a delay before Caddy verifies the SSL certificate with the CA and SSL starts to work. The node will return SSL errors until then.

## Submit the secret config file

Load the secret config file. This can only be done once.

```sh
cd secretMgmt
cargo run --bin loader -- --ip-addr <deployedIP>:1700 --secret data/key.sec --message data/secret.json --endpoint http://<deployedIP>:1300 --pcr0 <pcr0> --pcr1 <pcr1> --pcr2 <pcr2>
cd -
```

Where `data/secret.json` is the server config file