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

import Foundation
import SwiftASN1
import X509

struct CRL: PEMParseable, DERParseable {
	var version: Int64
	var issuer: DistinguishedName
	var thisUpdate: UTCTime
	var nextUpdate: UTCTime
	var revokedSerials: [CRLSerialInfo] = []
	var tbsBytes: ArraySlice<UInt8>
	var signatureAlgorithmOID: ASN1ObjectIdentifier
	var signatureBitBytes: ArraySlice<UInt8>
	static let defaultPEMDiscriminator: String = "X509 CRL"

	struct CRLSerialInfo: DERImplicitlyTaggable, CustomStringConvertible {
		let serial: Certificate.SerialNumber // ArraySlice<UInt8>
		let date: UTCTime
		init(derEncoded: SwiftASN1.ASN1Node, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws {
			guard case .constructed(let nodes) = derEncoded.content else { throw CRL.toError(node: derEncoded) }
			var nodesIter = nodes.makeIterator()
			let snBytes = try ArraySlice<UInt8>(derEncoded: &nodesIter)
			serial = Certificate.SerialNumber(bytes: snBytes)
			date = try UTCTime(derEncoded: &nodesIter)
		}

		static let defaultIdentifier: SwiftASN1.ASN1Identifier = .sequence
		func serialize(into coder: inout SwiftASN1.DER.Serializer, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws { } // not used
		var description: String { serial.description }
	}

	init(derEncoded node: SwiftASN1.ASN1Node) throws {
		guard case .constructed(let nodes) = node.content else { throw Self.toError(node: node) }
		var nodesIter = nodes.makeIterator()
		guard let tbsCertListNode = nodesIter.next() else { throw Self.toError(node: node) } // tbsCertList
		tbsBytes = tbsCertListNode.encodedBytes
		// Parse signatureAlgorithm (SEQUENCE { OID, optional params })
		guard let sigAlgNode = nodesIter.next() else { throw Self.toError(node: node) }
		guard case .constructed(let sigAlgNodes) = sigAlgNode.content else { throw Self.toError(node: sigAlgNode) }
		var sigAlgIter = sigAlgNodes.makeIterator()
		signatureAlgorithmOID = try ASN1ObjectIdentifier(derEncoded: &sigAlgIter)
		// Parse signatureValue (BIT STRING)
		let sigBitString = try ASN1BitString(derEncoded: &nodesIter)
		signatureBitBytes = sigBitString.bytes[...]
		// Parse tbsCertList fields
		guard case .constructed(let nodes1) = tbsCertListNode.content else { throw Self.toError(node: tbsCertListNode) }
		var nodes1Iter = nodes1.makeIterator()
		version = try Int64(derEncoded: &nodes1Iter)
		_ = nodes1Iter.next() // skip signature algorithm (repeated in tbsCertList)
		guard let issuerNode = nodes1Iter.next() else { throw Self.toError(node: tbsCertListNode) }
		issuer = try DistinguishedName(derEncoded: issuerNode)
		thisUpdate = try SwiftASN1.UTCTime(derEncoded: &nodes1Iter)
		nextUpdate = try SwiftASN1.UTCTime(derEncoded: &nodes1Iter)
		guard let n2 = nodes1Iter.next() else { throw Self.toError(node: tbsCertListNode) } // revokedCertificates
		guard case .constructed(let nodes3) = n2.content else { throw Self.toError(node: n2) }
		revokedSerials = nodes3.compactMap { try? CRLSerialInfo(derEncoded: $0) }
	}

	// OID constants for signature algorithms not publicly exposed by swift-asn1
	private static let oidEcdsaWithSHA256: ASN1ObjectIdentifier = [1, 2, 840, 10045, 4, 3, 2]
	private static let oidEcdsaWithSHA384: ASN1ObjectIdentifier = [1, 2, 840, 10045, 4, 3, 3]
	private static let oidEcdsaWithSHA512: ASN1ObjectIdentifier = [1, 2, 840, 10045, 4, 3, 4]
	private static let oidSha1WithRSAEncryption: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 1, 5]
	private static let oidEd25519: ASN1ObjectIdentifier = [1, 3, 101, 112]

	/// Map the CRL's signature algorithm OID to the corresponding `Certificate.SignatureAlgorithm`.
	var signatureAlgorithm: Certificate.SignatureAlgorithm? {
		switch signatureAlgorithmOID {
		case Self.oidEcdsaWithSHA256: return .ecdsaWithSHA256
		case Self.oidEcdsaWithSHA384: return .ecdsaWithSHA384
		case Self.oidEcdsaWithSHA512: return .ecdsaWithSHA512
		case .AlgorithmIdentifier.sha256WithRSAEncryption: return .sha256WithRSAEncryption
		case .AlgorithmIdentifier.sha384WithRSAEncryption: return .sha384WithRSAEncryption
		case .AlgorithmIdentifier.sha512WithRSAEncryption: return .sha512WithRSAEncryption
		case Self.oidSha1WithRSAEncryption: return .sha1WithRSAEncryption
		case Self.oidEd25519: return .ed25519
		default: return nil
		}
	}

	/// Verify the CRL signature against the issuing certificate's public key.
	func verifySignature(issuer: X509.Certificate) -> Bool {
		guard let sigAlg = signatureAlgorithm else { return false }
		return issuer.publicKey.isValidSignature(signatureBitBytes, for: tbsBytes, signatureAlgorithm: sigAlg)
	}

	var isValid: Bool {
		let c = Calendar.current
		let dc = c.dateComponents(in: TimeZone(identifier: "UTC")!, from: Date())
		guard let now = try? UTCTime(year: dc.year!, month: dc.month!, day: dc.day!, hours: dc.hour!, minutes: dc.minute!, seconds: dc.second!) else { return false }
		return thisUpdate <= now && now <= nextUpdate
	}

	static func toError(node: SwiftASN1.ASN1Node) -> NSError {
		NSError(domain: "CRL", code: 0, userInfo: [NSLocalizedDescriptionKey : "Invalid node \(node.identifier.description)"])
	}
}

struct CRLEntry {
	let certificateSerialNumber: String
	let revocationDate: Date
}



