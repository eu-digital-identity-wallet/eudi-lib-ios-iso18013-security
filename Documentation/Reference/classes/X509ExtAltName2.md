**CLASS**

# `X509ExtAltName2`

**Contents**

- [Properties](#properties)
  - `issuerAlternativeNamesAndTypes`
- [Methods](#methods)
  - `init(der:)`
  - `extensionObject(oid:)`
  - `extensionObject(oid:)`

```swift
public class X509ExtAltName2
```

## Properties
### `issuerAlternativeNamesAndTypes`

```swift
public var issuerAlternativeNamesAndTypes: [UInt8:String]?
```

Gets a collection of issuer alternative names from the IssuerAltName extension, (OID = 2.5.29.18).

## Methods
### `init(der:)`

```swift
public init(der: Data) throws
```

### `extensionObject(oid:)`

```swift
public func extensionObject(oid: OID) -> X509ExtensionAltName2?
```

Gets the extension information of the given OID enum.

### `extensionObject(oid:)`

```swift
public func extensionObject(oid: String) -> X509ExtensionAltName2?
```

Gets the extension information of the given OID code.
