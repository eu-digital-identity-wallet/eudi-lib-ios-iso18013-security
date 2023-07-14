**STRUCT**

# `SessionEncryption`

**Contents**

- [Properties](#properties)
  - `sessionRole`
  - `sessionCounter`
  - `errorCode`
  - `IDENTIFIER0`
  - `IDENTIFIER1`
  - `encryptionIdentifier`
  - `decryptionIdentifier`
  - `sessionKeys`
  - `deviceEngagementRawData`
  - `eReaderKeyRawData`
  - `handOver`
  - `transcript`
  - `sessionTranscriptBytes`
- [Methods](#methods)
  - `init(se:de:handOver:)`
  - `makeNonce(_:isEncrypt:)`
  - `HMACKeyDerivationFunction(sharedSecret:salt:info:)`
  - `encrypt(_:)`
  - `decrypt(_:)`
  - `getInfo(isEncrypt:)`
  - `makeKeyAgreementAndDeriveSessionKey(isEncrypt:)`

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
let sessionRole: SessionRole
```

### `sessionCounter`

```swift
public var sessionCounter: UInt32 = 1
```

### `errorCode`

```swift
var errorCode: UInt?
```

### `IDENTIFIER0`

```swift
static let IDENTIFIER0: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
```

### `IDENTIFIER1`

```swift
static let IDENTIFIER1: [UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
```

### `encryptionIdentifier`

```swift
var encryptionIdentifier: [UInt8]
```

### `decryptionIdentifier`

```swift
var decryptionIdentifier: [UInt8]
```

### `sessionKeys`

```swift
let sessionKeys: CoseKeyExchange
```

### `deviceEngagementRawData`

```swift
var deviceEngagementRawData: [UInt8]
```

### `eReaderKeyRawData`

```swift
let eReaderKeyRawData: [UInt8]
```

### `handOver`

```swift
let handOver: CBOR
```

### `transcript`

```swift
var transcript: SessionTranscript
```

### `sessionTranscriptBytes`

```swift
public var sessionTranscriptBytes: [UInt8]
```

SessionTranscript = [DeviceEngagementBytes,EReaderKeyBytes,Handover]

## Methods
### `init(se:de:handOver:)`

```swift
init?(se: SessionEstablishment, de: DeviceEngagement, handOver: CBOR)
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

### `makeNonce(_:isEncrypt:)`

```swift
func makeNonce(_ counter: UInt32, isEncrypt: Bool) throws -> AES.GCM.Nonce
```

Make nonce function to initialize the encryption or decryption

- Parameters:
  - counter: The message counter value shall be a 4-byte big-endian unsigned integer. For the first encryption with a session key, the message counter shall be set to 1. Before each following encryption with the same key, the message counter value shall be increased by 1
  - isEncrypt: is for encrypt?
- Returns: The IV (Initialization Vector) used for the encryption.

#### Parameters

| Name | Description |
| ---- | ----------- |
| counter | The message counter value shall be a 4-byte big-endian unsigned integer. For the first encryption with a session key, the message counter shall be set to 1. Before each following encryption with the same key, the message counter value shall be increased by 1 |
| isEncrypt | is for encrypt? |

### `HMACKeyDerivationFunction(sharedSecret:salt:info:)`

```swift
static func HMACKeyDerivationFunction(sharedSecret: SharedSecret, salt: [UInt8], info: Data) throws -> SymmetricKey
```

computation of HKDF symmetric key

### `encrypt(_:)`

```swift
mutating func encrypt(_ data: [UInt8]) throws -> [UInt8]?
```

encrypt data using current nonce as described in 9.1.1.5 Cryptographic operations

### `decrypt(_:)`

```swift
mutating func decrypt(_ ciphertext: [UInt8]) throws -> [UInt8]?
```

decryptes cipher data using the symmetric key

### `getInfo(isEncrypt:)`

```swift
func getInfo(isEncrypt: Bool) -> String
```

### `makeKeyAgreementAndDeriveSessionKey(isEncrypt:)`

```swift
func makeKeyAgreementAndDeriveSessionKey(isEncrypt: Bool) throws -> SymmetricKey?
```

Session keys are derived using ECKA-DH (Elliptic Curve Key Agreement Algorithm – Diffie-Hellman) as defined in BSI TR-03111
