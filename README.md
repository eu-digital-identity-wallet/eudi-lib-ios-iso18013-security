# eudi-lib-ios-iso18013-security

[![Swift](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security/actions/workflows/swift.yml/badge.svg)](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security/actions/workflows/swift.yml)

Implementation of mDoc security according to [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) standard
(0.9.0)

## Session encryption
Session encryption uses standard ephemeral key ECDH to establish session keys for authenticated symmetric encryption.
The ``SessionEncryption`` struct implements session encryption (for the mDoc currently)
It is initialized from a) the session establishment data received from the mdoc reader, b) the device engagement data generated from the mdoc and c) the handover data.
 
```swift
var sessionEncr = SessionEncryption(se: sessionEstablishmentObject, de: deviceEngagementObject, handOver: handOverObject)
let data = try sessionEncr.decrypt(sessionEstablishmentObject.data)!
```

## mdoc authentication
The security objective of mdoc authentication is to prevent cloning of the mdoc and to mitigate man in the middle attacks.
Currently the mdoc side is implemented (generation of device-auth)
Initialized from the session trascript object, the device private key and the reader ephemeral public key 
 
```swift
let mdocAuth = MdocAuthentication(transcript: sessionEncr.transcript, authKeys: authKeys)
let deviceAuth = try mdocAuth.getDeviceAuthForTransfer(docType: "org.iso.18013.5.1.mDL", deviceNameSpacesRawData: [0xA0], bUseDeviceSign: bUseDeviceSign)!
let ourDeviceAuthCBORbytes = deviceAuth.encode(options: CBOROptions())
```

## mdoc reader authentication
The data that the mdoc reader authenticates is the ReaderAuthentication structure
Currently the mdoc side is implemented (verification of reader-auth CBOR data)

```swift
let mdocAuth = MdocReaderAuthentication(transcript: sessionEncr.transcript)
guard let readerAuthRawCBOR = docR.readerAuthRawCBOR else { continue }
let b = try mdocAuth.validateReaderAuth(readerAuthCBOR: readerAuthRawCBOR, readerAuthCertificate: docR.readerCertificate!, itemsRequestRawData: docR.itemsRequestRawData!)
```

## Reference
Detailed documentation is provided [here](Documentation/Reference/README.md) 
