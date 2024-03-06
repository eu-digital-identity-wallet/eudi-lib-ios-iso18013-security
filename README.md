# EUDI Wallet ISO/IEC 18013-5 Security library for iOS

:heavy_exclamation_mark: **Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github-private/blob/main/profile/reference-implementation.md)

----

# eudi-lib-ios-iso18013-security

[![Swift](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security/actions/workflows/swift.yml/badge.svg)](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security/actions/workflows/swift.yml)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=eu-digital-identity-wallet_eudi-lib-ios-iso18013-security&metric=ncloc&token=270646d93c527944c1aca89437311971a792d62d)](https://sonarcloud.io/summary/new_code?id=eu-digital-identity-wallet_eudi-lib-ios-iso18013-security)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=eu-digital-identity-wallet_eudi-lib-ios-iso18013-security&metric=duplicated_lines_density&token=270646d93c527944c1aca89437311971a792d62d)](https://sonarcloud.io/summary/new_code?id=eu-digital-identity-wallet_eudi-lib-ios-iso18013-security)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=eu-digital-identity-wallet_eudi-lib-ios-iso18013-security&metric=reliability_rating&token=270646d93c527944c1aca89437311971a792d62d)](https://sonarcloud.io/summary/new_code?id=eu-digital-identity-wallet_eudi-lib-ios-iso18013-security)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=eu-digital-identity-wallet_eudi-lib-ios-iso18013-security&metric=vulnerabilities&token=270646d93c527944c1aca89437311971a792d62d)](https://sonarcloud.io/summary/new_code?id=eu-digital-identity-wallet_eudi-lib-ios-iso18013-security)


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

## Dependencies (to other libs)

* ASN1 DER Decoder for X.509 Certificate [ASN1Decoder](https://github.com/filom/ASN1Decoder)
* A Logging API for Swift: [swift-log](https://github.com/apple/swift-log)

## Reference
Detailed documentation is provided [here](Documentation/Reference/README.md) 

### Disclaimer
The released software is a initial development release version: 
-  The initial development release is an early endeavor reflecting the efforts of a short timeboxed period, and by no means can be considered as the final product.  
-  The initial development release may be changed substantially over time, might introduce new features but also may change or remove existing ones, potentially breaking compatibility with your existing code.
-  The initial development release is limited in functional scope.
-  The initial development release may contain errors or design flaws and other problems that could cause system or other failures and data loss.
-  The initial development release has reduced security, privacy, availability, and reliability standards relative to future releases. This could make the software slower, less reliable, or more vulnerable to attacks than mature software.
-  The initial development release is not yet comprehensively documented. 
-  Users of the software must perform sufficient engineering and additional testing in order to properly evaluate their application and determine whether any of the open-sourced components is suitable for use in that application.
-  We strongly recommend to not put this version of the software into production use.
-  Only the latest version of the software will be supported

### License details

Copyright (c) 2023 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
