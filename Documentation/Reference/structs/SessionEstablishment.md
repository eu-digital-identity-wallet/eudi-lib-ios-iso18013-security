**STRUCT**

# `SessionEstablishment`

**Contents**

- [Properties](#properties)
  - `eReaderKeyRawData`
  - `data`
  - `eReaderKey`

```swift
public struct SessionEstablishment
```

The mdoc reader creates the session establishment message.Contains the reader key and the encrypted mdoc request.
The mdoc uses the data from the session establishment message to derive the session keys and decrypt the mdoc request.

## Properties
### `eReaderKeyRawData`

```swift
public let eReaderKeyRawData: [UInt8]
```

### `data`

```swift
public let data: [UInt8]
```

### `eReaderKey`

```swift
public var eReaderKey: CoseKey?
```
