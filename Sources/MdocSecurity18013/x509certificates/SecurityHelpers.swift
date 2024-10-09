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
import Logging
import CryptoKit
import X509
import SwiftASN1

public enum CertificateUsage: Sendable {
	case mdocAuth
	case mdocReaderAuth
}

public enum NotAllowedExtension: String, CaseIterable, Sendable {
	case policyMappings = "2.5.29.33"
	case nameConstraints = "2.5.29.30"
	case policyConstraints = "2.5.29.36"
	case inhibitAnyPolicy = "2.5.29.54"
	case freshestCRL = "2.5.29.46"
}

public class SecurityHelpers {
	public static let nonAllowedExtensions: [String] = NotAllowedExtension.allCases.map(\.rawValue)
	
	public static func getPublicKeyx963(publicCertData: Data) -> Data? {
		guard let sc = SecCertificateCreateWithData(nil, Data(publicCertData) as CFData) else { return nil }
		return getPublicKeyx963(ref: sc)
	}
	
	public static func getPublicKeyx963(ref: SecCertificate) -> Data? {
		guard let secKey = SecCertificateCopyKey(ref) else { return nil }
		var error: Unmanaged<CFError>?
		guard let repr = SecKeyCopyExternalRepresentation(secKey, &error) else { return nil }
		return repr as Data
	}
	
	public static func isMdocX5cValid(secCerts: [SecCertificate], usage: CertificateUsage, rootCerts: [SecCertificate]) -> (isValid:Bool, validationMessages: [String], rootCert: SecCertificate?) {
		let now = Date(); var messages = [String]()
		var trust: SecTrust?; let policy = SecPolicyCreateBasicX509(); _ = SecTrustCreateWithCertificates(secCerts as CFArray, policy, &trust)
		guard let trust else { return (false, ["Not valid certificate for \(usage)"], nil) }
		// convert to swift-certificates object
		guard let secCert = secCerts.first else { return (false, ["Certificate not found"], nil) }
		let secData: Data = SecCertificateCopyData(secCert) as Data
		guard let x509cert = try? X509.Certificate(derEncoded: [UInt8](secData)) else { return (false,["Not valid certificate for \(usage)"], nil) }
		guard x509cert.notValidBefore <= now, now <= x509cert.notValidAfter else { return (false, ["Current date not in validity period of Certificate"], nil) }
		let valDays = Calendar.current.dateComponents([.day], from: x509cert.notValidBefore, to: x509cert.notValidAfter).day
		guard let valDays, valDays > 0 else { return (false, ["Invalid validity period"], nil) }
		guard !x509cert.subject.isEmpty, let cn = getCommonName(ref: secCert), !cn.isEmpty else { return (false, ["Missing Common Name of Reader Certificate"], nil) }
		guard !x509cert.signature.description.isEmpty else { return (false, ["Missing Signature data"], nil) }
		if x509cert.serialNumber.description.isEmpty { messages.append("Missing Serial number") }
		// not critical errors below
		if x509cert.hasDuplicateExtensions() { messages.append("Duplicate extensions in Certificate") }
		if usage == .mdocReaderAuth {
			verifyReaderAuthCert(x509cert, messages: &messages)
			if let gns = x509cert.getSubjectAlternativeNames(), let gn = gns.first(where: { switch $0 { case .rfc822Name(_): true; case .uniformResourceIdentifier(_): true;  default: false } }) { logger.info("Alternative name \(gn.description)")}
		}
		SecTrustSetPolicies(trust, policy)
		for rootCert in rootCerts {
			let certArray = [rootCert]
			SecTrustSetAnchorCertificates(trust, certArray as CFArray)
			SecTrustSetAnchorCertificatesOnly(trust, true)
			let serverTrustIsValid = trustIsValid(trust)
			if serverTrustIsValid {
				guard let x509root = try? X509.Certificate(derEncoded: [UInt8](SecCertificateCopyData(rootCert) as Data)) else { return (false, ["Bad root certificate"], rootCert) }
				guard x509root.notValidBefore <= now, now <= x509root.notValidAfter else { return (false, ["Current date not in validity period of Reader Root Certificate"], nil) }
				if usage == .mdocReaderAuth, let rootGns = x509root.getSubjectAlternativeNames(), let gns = x509cert.getSubjectAlternativeNames() {
					guard gns.elementsEqual(rootGns) else { return (false, ["Issuer data rfc822Name or uniformResourceIdentifier do not match with root cert."], nil) }
				}
				let bs = fetchCRLSerialNumbers(x509root)
				if !bs.isEmpty {
					if bs.contains(x509cert.serialNumber) { return (false, ["Revoked issued Certificate"], rootCert)}
					if bs.contains(x509root.serialNumber) { return (false,["Revoked Root Certificate"], rootCert)}
				}
				return (true, messages, rootCert)
			}
		} // next
		messages.insert("Certificate not matched with root certificates", at: 0	)
		return (false, messages, nil)
	}
	
	public static func trustIsValid(_ trust: SecTrust) -> Bool {
		var error: CFError?
		let isValid = SecTrustEvaluateWithError(trust, &error)
		if let error { logger.error("Error evaluating trust: \(error)") }
		return isValid
	}
	
	public static func fetchCRLSerialNumbers(_ x509root: X509.Certificate) -> [Certificate.SerialNumber] {
		var res = [Certificate.SerialNumber]()
		if let ext = x509root.extensions[oid: .X509ExtensionID.cRLDistributionPoints], let crlDistr = try? CRLDistributions(derEncoded: ext.value) {
			for crl in crlDistr.crls {
				guard let crlUrl = URL(string: crl.distributionPoint) else { continue }
				guard let pem = try? String(contentsOf: crlUrl) else { continue }
				guard let crl = try? CRL(pemEncoded: pem) else { continue }
				res.append(contentsOf: crl.revokedSerials.map(\.serial))
			}
		}
		return res
	}
	
	public static func verifyReaderAuthCert(_ x509: X509.Certificate, messages: inout [String]) {
		// check issuer
		if !x509.issuer.isEmpty { logger.info("Issuer \(x509.issuer.description)")} else { messages.append("Missing Issuer") }
		// check authority key identifier
		if let ext_aki = try? x509.extensions.authorityKeyIdentifier, let ext_aki_ki = ext_aki.keyIdentifier, !ext_aki_ki.isEmpty { logger.info("Authority key identifier \(ext_aki_ki.description)") } else { messages.append("Missing Authority Key Identifier") }
		// check subject key identifier
		let pk_data = Array(x509.publicKey.subjectPublicKeyInfoBytes)
		let ext_ski = try? x509.extensions.subjectKeyIdentifier
		if let ext_ski {
			logger.info("Subject key Identifier \(ext_ski.keyIdentifier.description)")
			let ski = Array(ext_ski.keyIdentifier)
			if ski == Array(Insecure.SHA1.hash(data: pk_data)) { logger.info("Subject Key Identifier equal to public key SHA1") } else { messages.append("Wrong Subject Key Identifier") }
		} else { messages.append("Missing Subject Key Identifier") }
		// check key usage
		if let keyUsage = try? x509.extensions.keyUsage, keyUsage.digitalSignature { logger.info("Subject public key is used for verifying Digital Signature")} else { messages.append("Key usage should be verifying Digital Certificate") }
		// check extended key usage
		if let extKeyUsage = try? x509.extensions.extendedKeyUsage, extKeyUsage.contains(ExtendedKeyUsage.Usage(oid: .extKeyUsageMdlReaderAuth)) { logger.info("Extended key usage contains mdlReaderAuth") } else { messages.append("Extended Key usage does not contain mdlReaderAuth") }
		// display extended OCSP extension
		if let ext_ocsp = try? x509.extensions.authorityInformationAccess, let infoAccesses = ext_ocsp.infoAccesses, let infoAccess = infoAccesses.first, infoAccess.method == .ocspServer, !infoAccess.location.description.isEmpty { logger.info("OCSP server location: \(infoAccess.location.description)") }
		if x509.signatureAlgorithm.isECDSA256or384or512 { logger.info("Signature algorithm is \(x509.signatureAlgorithm)")} else { messages.append("Signature algorithm must be ECDSA with SHA 256/384/512") }
		// check for not allowed critical extensions
		let criticalExtensionOIDs: [String] = x509.extensions.filter(\.critical).map(\.oid).map(\.description)
		let notAllowedCriticalExt = Set(criticalExtensionOIDs).intersection(Set(Self.nonAllowedExtensions))
		if notAllowedCriticalExt.isEmpty { logger.info("Critical extensions correct") } else { messages.append("Not allowed critical extensions \(notAllowedCriticalExt)") }
		// check crls existing
		if let crlExt1 = x509.extensions[oid: .X509ExtensionID.cRLDistributionPoints], let crlExt2 = try? CRLDistributionPointsExtension(crlExt1), !crlExt2.crls.isEmpty, crlExt2.crls.allSatisfy(\.isNotEmpty) { logger.info("CRL Distribution extension found") } else { messages.append("Missing CRL Distribution extension") }
	}
	
	public static func getCommonName(ref: SecCertificate) -> String? {
		var cfName: CFString?
		SecCertificateCopyCommonName(ref, &cfName)
		return cfName as String?
	}
}


