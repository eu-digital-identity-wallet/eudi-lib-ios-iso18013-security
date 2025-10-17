/// Utility functions that can be used for issuer authentication

/*
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
*/
import CryptoKit
import Foundation
import MdocDataModel18013
import SwiftCBOR

func getHash(_ d: DigestAlgorithmKind, bytes: [UInt8]) -> Data {
    switch d {
    case .SHA256:
        let h = SHA256.hash(data: Data(bytes))
        return h.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> Data in Data(p[0..<p.count]) }
    case .SHA384:
        let h = SHA384.hash(data: Data(bytes))
        return h.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> Data in Data(p[0..<p.count]) }
    case .SHA512:
        let h = SHA512.hash(data: Data(bytes))
        return h.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> Data in Data(p[0..<p.count]) }
    }
}

/// Validate a digest value included in the ``MobileSecurityObject`` structure
func validateDigest(for signedItem: IssuerSignedItem, dak: DigestAlgorithmKind, digest: [UInt8]?) -> Bool {
    guard let digest else { return false }
    let issuerSignedItemBytes = signedItem.encode(options: CBOROptions()).taggedEncoded.encode()
    let itemDigest = getHash(dak, bytes: issuerSignedItemBytes)
    if itemDigest == Data(digest) { return true }
    return false
}

func validateDigests(for ns: NameSpace, items: [IssuerSignedItem], dak: DigestAlgorithmKind, mso: MobileSecurityObject) -> (missing: [String], failed: [String]) {
    var missingElements = [String]()
    var failedElements = [String]()
    for item in items {
        guard let digest = mso.valueDigests[ns]?[item.digestID] else {
            missingElements.append(item.elementIdentifier)
            continue
        }
        guard validateDigest(for: item, dak: dak, digest: digest) else {
            failedElements.append(item.elementIdentifier)
            logger.info("Failed digest validation for \(item.elementIdentifier)")
            continue
        }
    }
    return (missing: missingElements, failed: failedElements)
}
