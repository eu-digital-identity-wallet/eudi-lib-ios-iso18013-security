**STRUCT**

# `SessionTranscript`

**Contents**

- [Properties](#properties)
  - `devEngRawData`
  - `eReaderRawData`
  - `handOver`

```swift
struct SessionTranscript
```

SessionTranscript = [DeviceEngagementBytes,EReaderKeyBytes,Handover]

## Properties
### `devEngRawData`

```swift
let devEngRawData: [UInt8]
```

device engagement bytes (NOT tagged)

### `eReaderRawData`

```swift
let eReaderRawData: [UInt8]
```

reader key bytes ( NOT tagged)

### `handOver`

```swift
let handOver: CBOR
```
