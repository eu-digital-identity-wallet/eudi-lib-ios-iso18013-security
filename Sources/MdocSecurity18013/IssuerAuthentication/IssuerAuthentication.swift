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

// IssuerAuthentication.swift
import Foundation
import SwiftCBOR
import MdocDataModel18013
import CryptoKit

/// Utility functions that can be used for issuer authentication
public struct IssuerAuthentication: Sendable {

	/// Calculate has of data according to a hash algorithm
	/// - Parameters:
	///   - d: Digest algorithm identifier
	///   - bytes: Bytes over which the hash is calculated
	/// - Returns: The hash value
	public static func getHash(_ d:DigestAlgorithmKind, bytes: [UInt8]) -> Data {
		switch d {
		case .SHA256: let h = SHA256.hash(data:Data(bytes)); return h.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> Data in Data(p[0..<p.count]) }
		case .SHA384: let h = SHA384.hash(data:Data(bytes)); return h.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> Data in Data(p[0..<p.count]) }
		case .SHA512: let h = SHA512.hash(data:Data(bytes)); return h.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> Data in Data(p[0..<p.count]) }
		}
	}
	
	/// Validate a digest values included in the ``MobileSecurityObject`` structure
	/// - Parameters:
	///   - signedItem: Issuer signed item
	///   - dak: Digest algorithm identifier
	///   - digest: Digest value included in the MSO structure
	/// - Returns: True if validation succeeds
	public static func validateDigest(for signedItem: IssuerSignedItem, dak: DigestAlgorithmKind, digest: [UInt8]?) -> Bool {
		guard let digest else {return false}
		let issuerSignedItemBytes = signedItem.encode(options: CBOROptions()).taggedEncoded.encode()
		let itemDigest = Self.getHash(dak, bytes: issuerSignedItemBytes)
		if itemDigest == Data(digest) { return true }
		return false
	}
	
	/// Validate all digest values included in the ``MobileSecurityObject`` structure
	/// - Parameters:
	///   - document: Issuser signed document
	///   - dak: Digest algorithm identifier
	///   - digest: Digest value included in the MSO structure
	/// - Returns: True if validation succeeds
	public static func validateDigests(for document: Document, mso: MobileSecurityObject) -> (Bool, [String: Bool]) {
		guard let issuerNamespaces = document.issuerSigned.issuerNameSpaces?.nameSpaces, let dak = DigestAlgorithmKind(rawValue: mso.digestAlgorithm) else { return (false, [:]) }
		var failedElements = [String: Bool]()
		var result = (true, failedElements)
		for (ns,items) in issuerNamespaces {
			for item in items {
				let ok = validateDigest(for: item, dak: dak, digest: mso.valueDigests[ns]?[item.digestID])
				if !ok {
					failedElements[item.elementIdentifier] = false
					logger.info("Failed digest validation for \(item.elementIdentifier)")
					result = (false, failedElements)
				}
			}
		}
		return result
	}


}
