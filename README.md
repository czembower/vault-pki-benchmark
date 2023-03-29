# vault-pki-benchmark

Tool to benchmark a Vault Enterprise PKI secrets engine using JWT
authentication. Requires that the auth method and secrets engine have been
configured in advance.

## Usage

```text
  -authPath string
        Path to Vault Auth Method
  -authRole string
        Vault Auth Method Role
  -certDomain string
        Domain name to issue certificates
  -enginePath string
        Path to Vault PKI Secrets Engine
  -engineRole string
        Path to PKI Engine Role
  -insecureTls
        If set, certificate validation will be skipped
  -jwtToken string
        JWT Token string
  -notest
        If unset, run once and return the token and certificate for verification
  -reuseToken
        Set to avoid authentication on each iteration
  -seconds int
        Duration of time in seconds to loop and create certificates (default 1)
  -strictTimeout
        Set to drop all open requests at timeout without waiting for the response
  -threads int
        Number of concurrent clients to run (default 1)
  -vaultAddr string
        Vault server address
  -vaultNamespace string
        Vault Namespace
```

## Example Output

```text
# vault-pki-benchmark \
  -vaultAddr https://vault.local:8200 \
  -jwtToken $(cat saToken) \
  -authPath jwt \
  -authRole myJwtRole \
  -vaultNamespace test \
  -enginePath pki_int \
  -engineRole myPkiRole \
  -certDomain local \
  -seconds 5 \
  -threads 64 \
  -notest \
  -reuseToken
Threads: 64
Duration: 5 seconds
2023-03-29 13:06:30.598320744 +0000 UTC
Timeout reached
Iterations: 1880
authSuccess: 1
authFail: 0
certSuccess: 1880
certFail: 0
certRate: 376 certs/sec
authSuccessRatio: 100
certSuccessRatio: 100
```
