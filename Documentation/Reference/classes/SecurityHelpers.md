**CLASS**

# `SecurityHelpers`

**Contents**

- [Properties](#properties)
  - `nonAllowedExtensions`
  - `ecdsaAlgOIDs`
- [Methods](#methods)
  - `now()`
  - `isValidMdlPublicKey(secCert:usage:rootCerts:checkCrl:maxValPeriod:)`
  - `trustIsValid(_:)`

```swift
public class SecurityHelpers
```

## Properties
### `nonAllowedExtensions`

```swift
public static var nonAllowedExtensions: [String] = NotAllowedExtension.allCases.map(\.rawValue)
```

### `ecdsaAlgOIDs`

```swift
public static var ecdsaAlgOIDs: [String]
```

## Methods
### `now()`

```swift
public static func now() -> Date
```

### `isValidMdlPublicKey(secCert:usage:rootCerts:checkCrl:maxValPeriod:)`

```swift
public static func isValidMdlPublicKey(secCert: SecCertificate, usage: CertificateUsage, rootCerts: [SecCertificate], checkCrl: Bool = true, maxValPeriod: UInt = UInt.max) -> (isValid:Bool, reason: String?, rootCert: SecCertificate?)
```

### `trustIsValid(_:)`

```swift
public static func trustIsValid(_ trust: SecTrust) -> Bool
```
