**EXTENSION**

# `Cose`
```swift
extension Cose
```

## Methods
### `makeDetachedCoseMac0(payloadData:key:alg:)`

```swift
public static func makeDetachedCoseMac0(payloadData: Data, key: SymmetricKey, alg: Cose.MacAlgorithm) -> Cose
```

Make an untagged COSE-Mac0 structure according to https://datatracker.ietf.org/doc/html/rfc8152#section-6.3 (How to Compute and Verify a MAC)
- Parameters:
  - payloadData: The serialized content to be MACed
  - key: ECDH-agreed key
  - alg: MAC algorithm
- Returns: A Cose structure with detached payload used for verification

#### Parameters

| Name | Description |
| ---- | ----------- |
| payloadData | The serialized content to be MACed |
| key | ECDH-agreed key |
| alg | MAC algorithm |

### `computeMACValue(_:key:alg:)`

```swift
public static func computeMACValue(_ dataToAuthenticate: Data, key: SymmetricKey, alg: Cose.MacAlgorithm) -> Data
```

Computes a message authenticated code for the data
- Parameters:
  - dataToAuthenticate: Data for which to compute the code
  - key: symmetric key
  - alg: HMAC algorithm variant
- Returns: The message authenticated code

#### Parameters

| Name | Description |
| ---- | ----------- |
| dataToAuthenticate | Data for which to compute the code |
| key | symmetric key |
| alg | HMAC algorithm variant |

### `makeDetachedCoseSign1(payloadData:deviceKey:alg:)`

```swift
public static func makeDetachedCoseSign1(payloadData: Data, deviceKey: CoseKeyPrivate, alg: Cose.VerifyAlgorithm) throws-> Cose
```

Create a detached COSE-Sign1 structure according to https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
- Parameters:
  - payloadData: Payload to be signed
  - deviceKey: static device private key (encoded with ANSI x.963 or stored in SE)
  - alg: The algorithm to sign with
- Returns: a detached COSE-Sign1 structure

#### Parameters

| Name | Description |
| ---- | ----------- |
| payloadData | Payload to be signed |
| deviceKey | static device private key (encoded with ANSI x.963 or stored in SE) |
| alg | The algorithm to sign with |

### `computeSignatureValue(_:deviceKey_x963:alg:)`

```swift
public static func computeSignatureValue(_ dataToSign: Data, deviceKey_x963: Data, alg: Cose.VerifyAlgorithm) throws -> Data
```

Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) signature of the provide data over an elliptic curve. Apple Crypto implementation is used
- Parameters:
  - dataToSign: Data to create the signature for (payload)
  - deviceKey_x963: x963 representation of the private key
  - alg: ``MdocDataModel18013/Cose.VerifyAlgorithm``
- Returns: The signature corresponding to the data

#### Parameters

| Name | Description |
| ---- | ----------- |
| dataToSign | Data to create the signature for (payload) |
| deviceKey_x963 | x963 representation of the private key |
| alg | `MdocDataModel18013/Cose.VerifyAlgorithm` |

### `validateDetachedCoseSign1(payloadData:publicKey_x963:)`

```swift
public func validateDetachedCoseSign1(payloadData: Data, publicKey_x963: Data) throws -> Bool
```

Validate (verify) a detached COSE-Sign1 structure according to https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
- Parameters:
  - payloadData: Payload data signed
  - publicKey_x963: public key corresponding the private key used to sign the data
- Returns: True if validation of signature succeeds

#### Parameters

| Name | Description |
| ---- | ----------- |
| payloadData | Payload data signed |
| publicKey_x963 | public key corresponding the private key used to sign the data |