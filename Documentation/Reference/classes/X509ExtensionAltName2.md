**CLASS**

# `X509ExtensionAltName2`

**Contents**

- [Properties](#properties)
  - `block`
  - `alternativeNamesAndTypes`
- [Methods](#methods)
  - `init(block:)`
  - `generalName(of:)`

```swift
public class X509ExtensionAltName2
```

## Properties
### `block`

```swift
let block: ASN1Object
```

### `alternativeNamesAndTypes`

```swift
var alternativeNamesAndTypes: [UInt8: String]
```

## Methods
### `init(block:)`

```swift
required init(block: ASN1Object)
```

### `generalName(of:)`

```swift
func generalName(of item: ASN1Object) -> (UInt8,String)?
```
