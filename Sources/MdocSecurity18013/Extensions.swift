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
//import ASN1Decoder

extension UInt32 {
  public var data: Data {
    var int = self
    return Data(bytes: &int, count: MemoryLayout<UInt32>.size)
  }
	
	/// Little endian encoding of bytes
  public var byteArrayLittleEndian: [UInt8] {
    return [
      UInt8((self & 0xFF000000) >> 24),
      UInt8((self & 0x00FF0000) >> 16),
      UInt8((self & 0x0000FF00) >> 8),
      UInt8(self & 0x000000FF)
    ]
  }
}

extension X509.Certificate.SignatureAlgorithm {
	var isECDSA256or384or512: Bool {
		switch self {
		case .ecdsaWithSHA256, .ecdsaWithSHA384, .ecdsaWithSHA512: true
		default: false
		}
	}
}

extension X509.Certificate {
	
	func getSubjectAlternativeNames() -> [GeneralName]? {
		guard let sa = try? extensions.subjectAlternativeNames, sa.count > 0 else { return nil }
		return Array(sa)
	}
	
	func hasDuplicateExtensions() -> Bool {
		let extensionsOids = extensions.map(\.oid)
		return Set(extensionsOids).count < extensionsOids.count
	}
}

extension ASN1ObjectIdentifier {
	static let extKeyUsageMdlReaderAuth: ASN1ObjectIdentifier = [1,0,18013,5,1,6]
  enum X509ExtensionID {
    static let cRLDistributionPoints: ASN1ObjectIdentifier = [2,5,29,31]
  }
}

public struct CRLDistributionPointsExtension {
	public var crls: [CRLDistribution] = []
	
	public init(_ ext: Certificate.Extension) throws {
		guard ext.oid == .X509ExtensionID.cRLDistributionPoints else {
			throw CertificateError.incorrectOIDForExtension(
				reason: "Expected \(ASN1ObjectIdentifier.X509ExtensionID.cRLDistributionPoints), got \(ext.oid)"
			)
		}
		let rootNode = try DER.parse(ext.value)
		let crlColl = try CRLDistributions(derEncoded: rootNode)
		crls = crlColl.crls
		logger.info("CRL Distribution Points: \(crls.map(\.distributionPoint))")		
	}
}

/// CRL distribution wrapper
public struct CRLDistributions {
	public var crls: [CRLDistribution] = []
}

extension CRLDistributions: DERImplicitlyTaggable {
	public func serialize(into coder: inout SwiftASN1.DER.Serializer, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws { }	// not needed
	
	public static var defaultIdentifier: SwiftASN1.ASN1Identifier {	.sequence  }
	
	public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws {
		crls = try DER.sequence(of: CRLDistribution.self, identifier: identifier, rootNode: rootNode)
	}
}

/// CRL distribution
public struct CRLDistribution {
	let distributionPoint: String
	var isNotEmpty: Bool { !distributionPoint.isEmpty }
}

extension CRLDistribution: DERImplicitlyTaggable {
	public func serialize(into coder: inout SwiftASN1.DER.Serializer, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws { }	// not needed
	
	public static var defaultIdentifier: SwiftASN1.ASN1Identifier {	.sequence	}
	
	public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws {
		self = try DER.sequence(rootNode, identifier: identifier) { nodes in
			guard let n0 = nodes.next(), case let .constructed(n1c) = n0.content, let n1 = n1c.first(where: { _ in true }), case let .constructed(n2c) = n1.content, let n2 = n2c.first(where: { _ in true }), let gn = try? GeneralName(derEncoded: n2), case let .uniformResourceIdentifier(url) = gn else { return CRLDistribution(distributionPoint: "") }
			return CRLDistribution(distributionPoint: url)
		}
	}
}

extension AuthorityInformationAccess {
	var infoAccesses: [AccessDescription]? {
		let mirror = Mirror(reflecting: self)
		for case let (label?, value) in mirror.children {
			if label == "descriptions" {
				return value as? [AccessDescription]
			}
		}
		return nil
	}
}


