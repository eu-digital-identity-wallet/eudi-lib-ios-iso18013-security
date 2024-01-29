**STRUCT**

# `DeviceAuthentication`

```swift
public struct DeviceAuthentication
```

Implementes the intermediate structure for DeviceAuthentication

This structure is not transfered, only computed
The mDL calculates this ephemeral MAC by performing KDF(ECDH(mDL private key, reader ephemeral public key)) and the mDL reader calculates this ephemeral MAC by performing KDF(ECDH(mDL public key, reader ephemeral private key)).
