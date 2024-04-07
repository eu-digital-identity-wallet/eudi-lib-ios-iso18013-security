import Foundation
import CryptoKit
import X509
import SwiftASN1

public enum CertificateUsage {
	case mdocAuth
	case mdocReaderAuth
}

public enum NotAllowedExtension: String, CaseIterable {
	case policyMappings = "2.5.29.33"
	case nameConstraints = "2.5.29.30"
	case policyConstraints = "2.5.29.36"
	case inhibitAnyPolicy = "2.5.29.54"
	case freshestCRL = "2.5.29.46"
}

public class SecurityHelpers {
	public static var nonAllowedExtensions: [String] = NotAllowedExtension.allCases.map(\.rawValue)
	
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
	
	public static func isMdocCertificateValid(secCert: SecCertificate, usage: CertificateUsage, rootCerts: [SecCertificate]) -> (isValid:Bool, reason: String?, rootCert: SecCertificate?) {
		let now = Date()
		var trust: SecTrust?; let policy = SecPolicyCreateBasicX509(); _ = SecTrustCreateWithCertificates(secCert, policy, &trust)
		guard let trust else { return (false, "Certificate not valid", nil) }
		let secData: Data = SecCertificateCopyData(secCert) as Data
		guard let x509test = try? X509.Certificate(derEncoded: [UInt8](secData)) else { return (false,"Missing certificate for \(usage)", nil) }
		guard !x509test.hasDuplicateExtensions() else { return (false, "Duplicate extensions in Certificate", nil) }
		guard !x509test.serialNumber.description.isEmpty else { return (false, "Missing Serial number", nil) }
		let valDays = Calendar.current.dateComponents([.day], from: x509test.notValidBefore, to: x509test.notValidAfter).day
		guard x509test.notValidBefore <= now, now <= x509test.notValidAfter else { return (false,"Current date not in validity period of Certificate", nil) }
		guard let valDays, valDays > 0 else { return (false,"Invalid validity period", nil) }
		guard !x509test.subject.isEmpty, let cn = getCommonName(ref: secCert), !cn.isEmpty else { return (false, "Missing Common Name of Reader Certificate", nil) }
		if usage == .mdocReaderAuth { 
			if let strErr = verifyReaderAuthCert(x509test) { return (false, strErr, nil) }
			if let gns = x509test.getSubjectAlternativeNames(), let gn = gns.first(where: { switch $0 { case .rfc822Name(_): true; case .uniformResourceIdentifier(_): true;  default: false } }) { logger.info("Alternative name \(gn.description)")}
		}
		SecTrustSetPolicies(trust, policy)
		for cert in rootCerts {
			let certArray = [cert]
			SecTrustSetAnchorCertificates(trust, certArray as CFArray)
			SecTrustSetAnchorCertificatesOnly(trust, true)
			let serverTrustIsValid = trustIsValid(trust)
			if serverTrustIsValid {
				guard let x509root = try? X509.Certificate(derEncoded: [UInt8](SecCertificateCopyData(cert) as Data)) else { return (false, "Bad root certificate", cert) }
				guard x509root.notValidBefore <= now, now <= x509root.notValidAfter else { return (false,"Current date not in validity period of Reader Root Certificate", nil) }
				if usage == .mdocReaderAuth, let rootGns = x509root.getSubjectAlternativeNames(), let gns = x509test.getSubjectAlternativeNames() {
					guard gns.elementsEqual(rootGns) else { return (false, "Issuer data rfc822Name or uniformResourceIdentifier do not match with root cert.", nil) }
				}
				if x509test.serialNumber == x509root.serialNumber { continue }
				let bs = fetchCRLSerialNumbers(x509root)
				if !bs.isEmpty {
					if bs.contains(x509test.serialNumber) { return (false, "Revoked Certificate for \(usage)", cert)}
					if bs.contains(x509root.serialNumber) { return (false,"Revoked Root Certificate", cert)}
				} 
				return (true, "Certificate match with root cert \(x509root.subject.description)", cert)
			}
		} // next
		return (false, "Certificate not matched with root certificates", nil)
	}
	
	public static func trustIsValid(_ trust: SecTrust) -> Bool {
		var error: CFError?
		let isValid = SecTrustEvaluateWithError(trust, &error)
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
	
	public static func verifyReaderAuthCert(_ x509: X509.Certificate) -> String? {
		// check issuer
		guard !x509.issuer.isEmpty else { return "Missing Issuer" }
		// check authority key identifier
		guard let ext_aki = try? x509.extensions.authorityKeyIdentifier, let ext_aki_ki = ext_aki.keyIdentifier, !ext_aki_ki.isEmpty else { return "Missing Authority Key Identifier" }
		// check subject key identifier
		let pk_data = Array(x509.publicKey.subjectPublicKeyInfoBytes)
		guard let ext_ski = try? x509.extensions.subjectKeyIdentifier, case let ski = Array(ext_ski.keyIdentifier), !ski.isEmpty, !pk_data.isEmpty else { return "Missing Subject Key Identifier" }
		guard ski == Array(Insecure.SHA1.hash(data: pk_data)) else { return "Wrong Subject Key Identifier" }
		// check key usage
		guard let keyUsage = try? x509.extensions.keyUsage, keyUsage.digitalSignature else { return "Key usage Digital Certificate should be mandatory" }
		// check extended key usage
		guard let extKeyUsage = try? x509.extensions.extendedKeyUsage, extKeyUsage.contains(ExtendedKeyUsage.Usage(oid: .extKeyUsageMdlReaderAuth)) else { return "Extended Key usage does not contain mdlReaderAuth" }
		// display extended OCSP extension
		if let ext_ocsp = try? x509.extensions.authorityInformationAccess, let infoAccesses = ext_ocsp.infoAccesses, let infoAccess = infoAccesses.first, infoAccess.method == .ocspServer, !infoAccess.location.description.isEmpty { logger.info("OCSP server location: \(infoAccess.location.description)") }
		guard x509.signatureAlgorithm.isECDSA256or384or512 else { return "Signature algorithm must be ECDSA with SHA 256/384/512" }
		guard !x509.signature.description.isEmpty else { return "Missing Signature data" }
		// check for not allowed critical extensions
		let criticalExtensionOIDs: [String] = x509.extensions.filter(\.critical).map(\.oid).map(\.description)
		guard Set(criticalExtensionOIDs).intersection(Set(Self.nonAllowedExtensions)).count == 0 else { return "Not allowed critical extension" }
		// check crls existing
		guard let crlExt1 = x509.extensions[oid: .X509ExtensionID.cRLDistributionPoints], let crlExt2 = try? CRLDistributionPointsExtension(crlExt1), !crlExt2.crls.isEmpty, crlExt2.crls.allSatisfy(\.isNotEmpty) else { return "Missing CRL Distribution extension" }
		return nil
	}
	
	public static func getCommonName(ref: SecCertificate) -> String? {
		var cfName: CFString?
		SecCertificateCopyCommonName(ref, &cfName)
		return cfName as String?
	}
}


