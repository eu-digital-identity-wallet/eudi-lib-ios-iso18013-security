**STRUCT**

# `MdocReaderAuthentication`

**Contents**

- [Methods](#methods)
  - `validateReaderAuth(readerAuthCBOR:readerAuthCertificate:itemsRequestRawData:rootCerts:)`
  - `init(transcript:)`

```swift
public struct MdocReaderAuthentication
```

Implements mdoc reader authentication

The data that the mdoc reader authenticates is the ReaderAuthentication structure
Currently the mdoc side is implemented (verification of reader-auth CBOR data)

## Methods
### `validateReaderAuth(readerAuthCBOR:readerAuthCertificate:itemsRequestRawData:rootCerts:)`

```swift
public func validateReaderAuth(readerAuthCBOR: CBOR, readerAuthCertificate: Data, itemsRequestRawData: [UInt8], rootCerts: [SecCertificate]? = nil) throws -> (Bool, String?)
```

Validate the reader auth structure contained in the the reader's initial message
- Parameters:
  - readerAuthCBOR: An untagged COSE-Sign1 structure containing the signature
  - readerAuthCertificate: The reader auth certificate decoded from above reader-auth structure. Contains the mdoc reader public key
  - itemsRequestRawData: Reader's item request raw data
- Returns: (True if verification of reader auth has valid signature, reason for certificate validation failure)

#### Parameters

| Name | Description |
| ---- | ----------- |
| readerAuthCBOR | An untagged COSE-Sign1 structure containing the signature |
| readerAuthCertificate | The reader auth certificate decoded from above reader-auth structure. Contains the mdoc reader public key |
| itemsRequestRawData | Reader’s item request raw data |

### `init(transcript:)`

```swift
public init(transcript: SessionTranscript)
```
