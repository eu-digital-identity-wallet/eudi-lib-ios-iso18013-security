**CLASS**

# `CertificateInfo`

**Contents**

- [Properties](#properties)
  - `ref`
  - `commonName`
  - `subjectSummary`
  - `email`
  - `thumbprint`
  - `serialNumber`
  - `expiryDate`
  - `failed`
  - `debugDescription`
- [Methods](#methods)
  - `init(ref:)`
  - `trustIsValid(_:)`
  - `getValidityPeriod()`
  - `getCertInfo(certData:)`

```swift
public class CertificateInfo: CustomDebugStringConvertible
```

## Properties
### `ref`

```swift
let ref: SecCertificate
```

### `commonName`

```swift
lazy public var commonName: String? = {
  var cfName: CFString?
  SecCertificateCopyCommonName(ref, &cfName)
  return cfName as String?
}()
```

### `subjectSummary`

```swift
lazy public var subjectSummary: String? = {
  var cfSummary: CFString?
  cfSummary = SecCertificateCopySubjectSummary(ref)
  return cfSummary as String?
}()
```

### `email`

```swift
lazy public var email: String? = {
  var cfEmails: CFArray?
  SecCertificateCopyEmailAddresses(ref, &cfEmails)
  guard let emails = cfEmails as! Array<String>? else {return nil}
  return emails.count > 0 ? emails[0] : ""
}()
```

### `thumbprint`

```swift
lazy public var thumbprint: String = {
  let der = SecCertificateCopyData(ref) as Data
  return Array(Insecure.SHA1.hash(data: der)).reduce(into: "") {
    var s = String($1, radix: 16)
    if s.count == 1 {s = "0" + s}
    if $0.count > 0 { $0 += ":" }
    if $0.count == 39 { $0 += " " }
    $0 += s.uppercased()
  }
}()
```

### `serialNumber`

```swift
lazy public var serialNumber: String = {
  var cfError: Unmanaged<CFError>?
  guard let snRef = SecCertificateCopySerialNumberData(ref, &cfError) else { return "" }
  return (snRef as Data).bytes.toHexString().uppercased()
}()
```

### `expiryDate`

```swift
lazy public var expiryDate: Date? = {
  guard let x509 = try? X509Certificate(der: SecCertificateCopyData(ref) as Data) else { return nil }
  return x509.notAfter
}()
```

### `failed`

```swift
public var failed: Bool?
```

### `debugDescription`

```swift
public var debugDescription: String
```

## Methods
### `init(ref:)`

```swift
public init(ref: SecCertificate)
```

### `trustIsValid(_:)`

```swift
func trustIsValid(_ trust: SecTrust) -> Bool
```

### `getValidityPeriod()`

```swift
public func getValidityPeriod() -> (Date, Date)?
```

### `getCertInfo(certData:)`

```swift
public static func getCertInfo(certData: Data?) -> (SecCertificate?, CertificateInfo?)
```
