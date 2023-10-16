**STRUCT**

# `IssuerAuthentication`

**Contents**

- [Properties](#properties)
  - `isoDateFormatter`
- [Methods](#methods)
  - `getHash(_:bytes:)`
  - `validateDigest(for:dak:digest:)`
  - `validateDigests(for:mso:)`

```swift
public struct IssuerAuthentication
```

Utility functions that can be used for issuer authentication

## Properties
### `isoDateFormatter`

```swift
public static var isoDateFormatter: ISO8601DateFormatter = {let df = ISO8601DateFormatter(); df.formatOptions = [.withFullDate, .withTime, .withTimeZone, .withColonSeparatorInTime, .withDashSeparatorInDate]; return df}()
```

## Methods
### `getHash(_:bytes:)`

```swift
public static func getHash(_ d:DigestAlgorithmKind, bytes: [UInt8]) -> Data
```

Calculate has of data according to a hash algorithm
- Parameters:
  - d: Digest algorithm identifier
  - bytes: Bytes over which the hash is calculated
- Returns: The hash value

#### Parameters

| Name | Description |
| ---- | ----------- |
| d | Digest algorithm identifier |
| bytes | Bytes over which the hash is calculated |

### `validateDigest(for:dak:digest:)`

```swift
public static func validateDigest(for signedItem: IssuerSignedItem, dak: DigestAlgorithmKind, digest: [UInt8]?) -> Bool
```

Validate a digest values included in the ``MobileSecurityObject`` structure
- Parameters:
  - signedItem: Issuer signed item
  - dak: Digest algorithm identifier
  - digest: Digest value included in the MSO structure
- Returns: True if validation succeeds

#### Parameters

| Name | Description |
| ---- | ----------- |
| signedItem | Issuer signed item |
| dak | Digest algorithm identifier |
| digest | Digest value included in the MSO structure |

### `validateDigests(for:mso:)`

```swift
public static func validateDigests(for document: Document, mso: MobileSecurityObject) -> (Bool, [String: Bool])
```

Validate all digest values included in the ``MobileSecurityObject`` structure
- Parameters:
  - document: Issuser signed document
  - dak: Digest algorithm identifier
  - digest: Digest value included in the MSO structure
- Returns: True if validation succeeds

#### Parameters

| Name | Description |
| ---- | ----------- |
| document | Issuser signed document |
| dak | Digest algorithm identifier |
| digest | Digest value included in the MSO structure |