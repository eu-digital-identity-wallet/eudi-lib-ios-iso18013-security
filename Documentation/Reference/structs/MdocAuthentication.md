**STRUCT**

# `MdocAuthentication`

**Contents**

- [Properties](#properties)
  - `transcript`
  - `authKeys`
  - `sessionTranscriptBytes`
- [Methods](#methods)
  - `makeMACKeyAggrementAndDeriveKey(deviceAuth:)`
  - `getDeviceAuthForTransfer(docType:deviceNameSpacesRawData:bUseDeviceSign:)`

```swift
struct MdocAuthentication
```

Implements mdoc authentication

The security objective of mdoc authentication is to prevent cloning of the mdoc and to mitigate man in the middle attacks.
Currently the mdoc side is implemented (generation of device-auth)
Initialized from the session trascript object, the device private key and the reader ephemeral public key 

```swift
let mdocAuth = MdocAuthentication(transcript: sessionEncr.transcript, authKeys: authKeys)
```

## Properties
### `transcript`

```swift
let transcript: SessionTranscript
```

### `authKeys`

```swift
let authKeys: CoseKeyExchange
```

### `sessionTranscriptBytes`

```swift
var sessionTranscriptBytes: [UInt8]
```

## Methods
### `makeMACKeyAggrementAndDeriveKey(deviceAuth:)`

```swift
func makeMACKeyAggrementAndDeriveKey(deviceAuth: DeviceAuthentication) throws -> SymmetricKey?
```

Calculate the ephemeral MAC key, by performing ECKA-DH (Elliptic Curve Key Agreement Algorithm – Diffie-Hellman)
The inputs shall be the SDeviceKey.Priv and EReaderKey.Pub for the mdoc and EReaderKey.Priv and SDeviceKey.Pub for the mdoc reader.

### `getDeviceAuthForTransfer(docType:deviceNameSpacesRawData:bUseDeviceSign:)`

```swift
public func getDeviceAuthForTransfer(docType: String, deviceNameSpacesRawData: [UInt8], bUseDeviceSign: Bool = false) throws -> DeviceAuth?
```

Generate a ``DeviceAuth`` structure used for mdoc-authentication
- Parameters:
  - docType: docType of the document to authenticate
  - deviceNameSpacesRawData: device-name spaces raw data. Usually is a CBOR-encoded empty dictionary
  - bUseDeviceSign: Specify true for device authentication (false is default)
- Returns: DeviceAuth instance

#### Parameters

| Name | Description |
| ---- | ----------- |
| docType | docType of the document to authenticate |
| deviceNameSpacesRawData | device-name spaces raw data. Usually is a CBOR-encoded empty dictionary |
| bUseDeviceSign | Specify true for device authentication (false is default) |