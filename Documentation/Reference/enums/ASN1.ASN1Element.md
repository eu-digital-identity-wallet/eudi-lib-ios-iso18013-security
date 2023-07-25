**ENUM**

# `ASN1.ASN1Element`

**Contents**

- [Cases](#cases)
  - `seq(elements:)`
  - `integer(int:)`
  - `bytes(data:)`
  - `constructed(tag:elem:)`
  - `unknown`

```swift
indirect enum ASN1Element
```

## Cases
### `seq(elements:)`

```swift
case seq(elements: [ASN1Element])
```

### `integer(int:)`

```swift
case integer(int: Int)
```

### `bytes(data:)`

```swift
case bytes(data: Data)
```

### `constructed(tag:elem:)`

```swift
case constructed(tag: Int, elem: ASN1Element)
```

### `unknown`

```swift
case unknown
```
