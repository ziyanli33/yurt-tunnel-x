# YurtTunnel X
In OpenYurt, we introduced a special component `YurtTunnel` to deal with the cloud-side communication. Reverse tunnel is a common way to solve cross-network communication, and `YurtTunnel` is also a reverse tunnel. It is a typical C/S structure component, consisting of `Yurt-Tunnel-Server` deployed in the cloud and `Yurt-Tunnel-Agent` deployed on edge nodes. 

## Initiative
`Yurttunnel X` is a standalone repository focused on `YurtTunnel` component only, as opposed to the huge repo [OpenYurt](https://github.com/openyurtio/openyurt/tree/v1.1.1) which includes other components such as `yurt-controller-manager`, `yurt-hub`, `yurtctl` etc.

`Yurttunnel X` also supports local testing and environment setup, featuring a kubernetes-free environment, where certificate rotation, DNS and iptables management are disabled.

> As `YurtTunnel` is going to be deprecated starting from `OpenYurt` v1.3 and onwards(replaced by [Raven](https://openyurt.io/docs/next/core-concepts/raven/)), this repository is forked and modified from `OpenYurt` v1.3.

## Core Concepts
Please refer to the [official docs](https://openyurt.io/docs/core-concepts/yurttunnel/)

## Run Locally
### 1. Add Node Name Resolve
```
sudo echo "127.0.0.1 yurt-edge-1" >> /etc/hosts
```
### 2. Build Binaries & Generate Root CAs
```
make build
make certs
make services # start tunnel server, tunnel agent & simple https server
```
### 3. Run Services
Run the following 3 commands in separate terminals
```
rm -f /tmp/interceptor-proxier.sock && bin/yurt-tunnel-server --no-cloud-ca-cert=certs/ca.crt --no-cloud-ca-key=certs/ca.key
```
```
bin/yurt-tunnel-agent --node-name=yurt-edge-1 \
							--node-ip=127.0.0.1 \
							--tunnelserver-addr=127.0.0.1:10262 \
							--no-cloud-ca-cert=certs/ca.crt \
							--no-cloud-ca-key=certs/ca.key
```
```
bin/simple-https-server --root-ca-cert=certs/ca.crt --root-ca-key=certs/ca.key
```
### 3. Send Https Request
> It is important to set "Host" header while iptables controller is not enabled and DNAT is skipped to facilitate testing.
```
curl --insecure --request GET 'https://127.0.0.1:10263' \
--header 'Host: yurt-edge-1:9000'
```
The response should be a line of text message 
```
This is an example server.
```

