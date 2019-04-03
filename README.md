# step-sds
Secret discovery service (SDS), simplifying the certificate management.

## mTLS initialization

### Using step

We are going to use [step](https://github.com/smallstep/cli) to initialize a PKI
to do mTLS between [Envoy](https://www.envoyproxy.io) and our SDS server.

Assuming that the SDS is running on sds.smallstep.com and we name the envoy
client certificate as envoy.smallstep.com we can just run:

```sh
# Root and intermediate
step certificate create --profile root-ca "Smallstep SDS Root CA" root.crt root.key
step certificate create --profile intermediate-ca --ca root.crt --ca-key root.key "Smallstep SDS Intermediate CA" int.crt int.key

# Step SDS
step certificate create --profile leaf --ca int.crt --ca-key int.key --no-password --insecure --not-after 87600h sds.smallstep.com sds.pem sds.key
step certificate bundle sds.pem int.crt sds.crt

# Envoy
step certificate create --profile leaf --ca int.crt --ca-key int.key --no-password --insecure --not-after 87600h envoy.smallstep.com envoy.pem envoy.key
step certificate bundle envoy.pem int.crt envoy.crt
```
