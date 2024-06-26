**STRUCT**

# `SessionEncryption`

**Contents**

- [Properties](#properties)
  - `sessionRole`
  - `sessionKeys`
  - `transcript`
  - `sessionTranscriptBytes`
- [Methods](#methods)
  - `init(se:de:handOver:)`
  - `encrypt(_:)`
  - `decrypt(_:)`

```swift
public struct SessionEncryption
```

Session encryption uses standard ephemeral key ECDH to establish session keys for authenticated symmetric encryption.
The ``SessionEncryption`` struct implements session encryption (for the mDoc currently)
It is initialized from a) the session establishment data received from the mdoc reader, b) the device engagement data generated from the mdoc and c) the handover data.

```swift
var se = SessionEncryption(se: sessionEstablishmentObject, de: deviceEngagementObject, handOver: handOverObject)
```

## Properties
### `sessionRole`

```swift
public let sessionRole: SessionRole
```

### `sessionKeys`

```swift
public let sessionKeys: CoseKeyExchange
```

### `transcript`

```swift
public var transcript: SessionTranscript
```

### `sessionTranscriptBytes`

```swift
public var sessionTranscriptBytes: [UInt8]
```

SessionTranscript = [DeviceEngagementBytes,EReaderKeyBytes,Handover]

## Methods
### `init(se:de:handOver:)`

```swift
public init?(se: SessionEstablishment, de: DeviceEngagement, handOver: CBOR)
```

Initialization of session encryption for the mdoc
- Parameters:
  - se: session establishment data from the mdoc reader
  - de: device engagement created by the mdoc
  - handOver: handover object according to the transfer protocol

#### Parameters

| Name | Description |
| ---- | ----------- |
| se | session establishment data from the mdoc reader |
| de | device engagement created by the mdoc |
| handOver | handover object according to the transfer protocol |

### `encrypt(_:)`

```swift
mutating public func encrypt(_ data: [UInt8]) throws -> [UInt8]?
```

encrypt data using current nonce as described in 9.1.1.5 Cryptographic operations

### `decrypt(_:)`

```swift
mutating public func decrypt(_ ciphertext: [UInt8]) throws -> [UInt8]?
```

decryptes cipher data using the symmetric key
