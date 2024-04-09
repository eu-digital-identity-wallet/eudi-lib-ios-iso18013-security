//
//  File.swift
//  
//
//  Created by ffeli on 22/11/2022.
/*
 TBSCertList  ::=  SEQUENCE  {
 *     version                 Version OPTIONAL,
 *                             -- if present, must be v2
 *     signature               AlgorithmIdentifier,
 *     issuer                  Name,
 *     thisUpdate              ChoiceOfTime,
 *     nextUpdate              ChoiceOfTime OPTIONAL,
 *     revokedCertificates     SEQUENCE OF SEQUENCE  {
 *         userCertificate         CertificateSerialNumber,
 *         revocationDate          ChoiceOfTime,
 *         crlEntryExtensions      Extensions OPTIONAL
 *                                 -- if present, must be v2
 *         }  OPTIONAL,
 *     crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 *                                  -- if present, must be v2
 *     }
 * </pre>*/
import Foundation
import SwiftASN1
import X509

struct CRL: PEMParseable, DERParseable {
	var serialNumber: Int64
	var issuer: DistinguishedName
	var validity: UTCTime
	var subject: UTCTime
	var revokedSerials: [CRLSerialInfo] = []
	static var defaultPEMDiscriminator: String = "X509 CRL"
	
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
		
		static var defaultIdentifier: SwiftASN1.ASN1Identifier = .sequence
		func serialize(into coder: inout SwiftASN1.DER.Serializer, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws { } // not used
		var description: String { serial.description }
	}
	
	init(derEncoded node: SwiftASN1.ASN1Node) throws {
		guard case .constructed(let nodes) = node.content else { throw Self.toError(node: node) }
		var nodesIter = nodes.makeIterator()
		guard let n1 = nodesIter.next() else { throw Self.toError(node: node) } // tbsCertificate
		guard case .constructed(let nodes1) = n1.content else { throw Self.toError(node: n1) }
		var nodes1Iter = nodes1.makeIterator()
		serialNumber = try Int64(derEncoded: &nodes1Iter)
		_ = nodes1Iter.next() // skip signature
		issuer = try DistinguishedName(derEncoded: &nodes1Iter)
		validity = try SwiftASN1.UTCTime(derEncoded: &nodes1Iter)
		subject = try SwiftASN1.UTCTime(derEncoded: &nodes1Iter)
		guard let n2 = nodes1Iter.next() else { throw Self.toError(node: n1) } // subject public key info
		guard case .constructed(let nodes3) = n2.content else { throw Self.toError(node: n2) }
		revokedSerials = nodes3.compactMap { try? CRLSerialInfo(derEncoded: $0) }
	}
	
	static func toError(node: SwiftASN1.ASN1Node) -> NSError {
		NSError(domain: "CRL", code: 0, userInfo: [NSLocalizedDescriptionKey : "Invalid node \(node.identifier.description)"])
	}
}

struct CRLEntry {
	let certificateSerialNumber: String
	let revocationDate: Date
}



