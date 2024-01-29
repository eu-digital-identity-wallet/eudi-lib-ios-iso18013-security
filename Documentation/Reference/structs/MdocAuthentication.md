**STRUCT**

# `MdocAuthentication`

**Contents**

- [Methods](#methods)
  - `init(transcript:authKeys:)`
  - `getDeviceAuthForTransfer(docType:deviceNameSpacesRawData:dauthMethod:)`

```swift
public struct MdocAuthentication
```

Implements mdoc authentication

The security objective of mdoc authentication is to prevent cloning of the mdoc and to mitigate man in the middle attacks.
Currently the mdoc side is implemented (generation of device-auth)
Initialized from the session transcript object, the device private key and the reader ephemeral public key 

```swift
let mdocAuth = MdocAuthentication(transcript: sessionEncr.transcript, authKeys: authKeys)
```

## Methods
### `init(transcript:authKeys:)`

```swift
public init(transcript: SessionTranscript, authKeys: CoseKeyExchange)
```

### `getDeviceAuthForTransfer(docType:deviceNameSpacesRawData:dauthMethod:)`

```swift
public func getDeviceAuthForTransfer(docType: String, deviceNameSpacesRawData: [UInt8] = [0xA0], dauthMethod: DeviceAuthMethod) throws -> DeviceAuth?
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