**STRUCT**

# `SessionData`

**Contents**

- [Properties](#properties)
  - `data`
  - `status`
- [Methods](#methods)
  - `init(cipher_data:status:)`

```swift
public struct SessionData
```

Message data transfered between mDL and mDL reader

## Properties
### `data`

```swift
public let data: [UInt8]?
```

### `status`

```swift
public let status: UInt64?
```

## Methods
### `init(cipher_data:status:)`

```swift
public init(cipher_data: [UInt8]? = nil, status: UInt64? = nil)
```
