**STRUCT**

# `DeviceAuthentication`

**Contents**

- [Properties](#properties)
  - `sessionTranscript`
  - `docType`
  - `deviceNameSpacesRawData`

```swift
public struct DeviceAuthentication
```

Implementes the intermediate structure for DeviceAuthentication

This structure is not transfered, only computed
The mDL calculates this ephemeral MAC by performing KDF(ECDH(mDL private key, reader ephemeral public key)) and the mDL reader calculates this ephemeral MAC by performing KDF(ECDH(mDL public key, reader ephemeral private key)).

## Properties
### `sessionTranscript`

```swift
let sessionTranscript: SessionTranscript
```

### `docType`

```swift
let docType: String
```

### `deviceNameSpacesRawData`

```swift
let deviceNameSpacesRawData: [UInt8]
```
