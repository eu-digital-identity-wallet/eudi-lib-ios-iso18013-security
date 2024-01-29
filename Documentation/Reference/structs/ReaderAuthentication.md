**STRUCT**

# `ReaderAuthentication`

```swift
public struct ReaderAuthentication
```

Implements the intermediate structure for reader authentication

This structure is not transfered, only computed
The mdoc calculates this ephemeral MAC by performing KDF(ECDH(mdoc private key, reader ephemeral public key)) and the mdoc reader calculates this ephemeral MAC by performing KDF(ECDH(mdoc public key, reader ephemeral private key)).
