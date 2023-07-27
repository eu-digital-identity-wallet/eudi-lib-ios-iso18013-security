**ENUM**

# `CertDataElement`

**Contents**

- [Cases](#cases)
  - `serialNumber`
  - `publicKeyAlgorithm`
  - `signatureAlgorithm`
  - `thumbprint`
  - `issuer`
  - `subject`
  - `validFrom`
  - `validUntil`
  - `issuingCountry`
  - `valid`

```swift
enum CertDataElement: String
```

## Cases
### `serialNumber`

```swift
case serialNumber = "certificate_serial_number"
```

### `publicKeyAlgorithm`

```swift
case publicKeyAlgorithm = "certificate_public_key_algorithm"
```

### `signatureAlgorithm`

```swift
case signatureAlgorithm = "certificate_signature_algorithm"
```

### `thumbprint`

```swift
case thumbprint = "certificate_thumbprint"
```

### `issuer`

```swift
case issuer = "certificate_issuer"
```

### `subject`

```swift
case subject = "certificate_subject"
```

### `validFrom`

```swift
case validFrom = "certificate_valid_from"
```

### `validUntil`

```swift
case validUntil = "certificate_valid_until"
```

### `issuingCountry`

```swift
case issuingCountry = "issuing_country"
```

### `valid`

```swift
case valid = "validity_info"
```
