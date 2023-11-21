 /*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

// IssuerAuthentication.swift
import Foundation
import SwiftCBOR
import MdocDataModel18013
import CryptoKit

/// Utility functions that can be used for issuer authentication
public struct IssuerAuthentication {
	public static var isoDateFormatter: ISO8601DateFormatter = {let df = ISO8601DateFormatter(); df.formatOptions = [.withFullDate, .withTime, .withTimeZone, .withColonSeparatorInTime, .withDashSeparatorInDate]; return df}()

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
