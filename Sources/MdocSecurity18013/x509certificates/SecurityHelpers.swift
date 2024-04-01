 import Foundation
 import CryptoKit
 import ASN1Decoder

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
	
	public static var ecdsaAlgOIDs: [String] { [OID.ecdsaWithSHA256.rawValue, "1.2.840.10045.4.3.3", OID.ecdsaWithSHA512.rawValue ] }
	
	public static func isValidMdlPublicKey(secCert: SecCertificate, usage: CertificateUsage, rootCerts: [SecCertificate]) -> (isValid:Bool, reason: String?, rootCert: SecCertificate?) {
		var trust: SecTrust?; let policy = SecPolicyCreateBasicX509(); _ = SecTrustCreateWithCertificates(secCert, policy, &trust)
		guard let trust else { return (false, "Certificate not valid", nil) }
		let secData: Data = SecCertificateCopyData(secCert) as Data
		let x509test = try? X509Certificate(der: secData)
		guard let x509test, let notAfter = x509test.notAfter, let notBefore = x509test.notBefore else { return (false,"Missing certificate for \(usage)", nil) }
		guard !ASN1Object.hasDuplicateExtensions(der: secData) else { return (false, "Duplicate extensions in Certificate", nil) }
		guard let sn = x509test.serialNumber else { return (false, "Missing Serial number", nil) }
		let valDays = Calendar.current.dateComponents([.day], from: notBefore, to: notAfter).day
		guard x509test.checkValidity(Date()) else { return (false,"Current date not in validity period of Reader Certificate", nil) }
		guard let valDays, valDays > 0 else { return (false,"Invalid validity period", nil) }
		guard let cn = x509test.subject(oid: .commonName), cn.first != nil else { return (false, "Missing Common Name of Reader Certificate", nil) }
		let (errAlt, dictAltNames) = if usage == .mdocReaderAuth { getAlternativeNames(secCert, x509test) } else { (nil,[:]) }
		if let errAlt { return (false, errAlt, nil) }
		SecTrustSetPolicies(trust, policy)
		for cert in rootCerts {
			let certArray = [cert]
			SecTrustSetAnchorCertificates(trust, certArray as CFArray)
			SecTrustSetAnchorCertificatesOnly(trust, true)
			let serverTrustIsValid = trustIsValid(trust)
			if serverTrustIsValid {
				guard let x509root = try? X509Certificate(der: SecCertificateCopyData(cert) as Data), x509root.notAfter != nil, x509root.notBefore != nil else { return (false, "Bad root certificate", cert) }
				guard x509root.checkValidity(Date()) else { return (false,"Current date not in validity period of Reader Root Certificate", nil) }
				if usage == .mdocReaderAuth {
					guard let x509root2 = try? X509ExtAltName2(der: SecCertificateCopyData(cert) as Data) else { return (false, "Issuer root data not in cert.", nil) }
					guard let dictAltNamesRoot = x509root2.issuerAlternativeNamesAndTypes, dictAltNamesRoot == dictAltNames else { return (false, "Issuer data rfc822Name or uniformResourceIdentifier do not match with root cert.", nil) }
				}
				if let test_sn = x509test.serialNumber, let root_sn = x509root.serialNumber, test_sn == root_sn { continue }
				let bs = checkCrl(x509test, x509root)
				if let bs, bs.contains(sn) { return (false,"Revoked Certificate for \(usage)", cert)}
				if let bs, let snr = x509root.serialNumber, bs.contains(snr) { return (false,"Revoked Root Certificate", cert)}
				return (true, "Certificate match with root cert \(x509root.subjectDistinguishedName ?? "N/A")", cert)
			}
		} // next
		return (false, "Certificate not matched with root certificates", nil)
	}
	
	public static func trustIsValid(_ trust: SecTrust) -> Bool {
		var error: CFError?
		let isValid = SecTrustEvaluateWithError(trust, &error)
		return isValid
	}
	
	public static func checkCrl(_ x509test: X509Certificate, _ x509root: X509Certificate) -> [Data]? {
		if let ext = x509root.extensionObject(oid: .cRLDistributionPoints) as? X509Certificate.CRLDistributionPointsExtension, let crls = ext.crls {
			for crl in crls {
				guard let crlUrl = URL(string: crl) else { return nil }
				guard let crlData = try? Data(contentsOf: crlUrl) else { return nil }
				let crl = try? X509CRL(pem: crlData);  let bs = crl?.badSerials
				return bs
			}
		}
		return nil
	}
	
	public static func getAlternativeNames(_ secCert: SecCertificate, _ x509test: X509Certificate) -> (String?,[UInt8: String]?) {
		guard x509test.version != nil else { return ("Missing Version", nil) };
		guard x509test.issuerOIDs.count > 0 else { return ("Missing Issuer", nil) }
		guard let ext_aki = x509test.extensionObject(oid: .authorityKeyIdentifier) as? X509Certificate.AuthorityKeyIdentifierExtension, ext_aki.keyIdentifier != nil else { return ("Missing Authority Key Identifier of Reader Certificate", nil) }
		guard let ext_ski = x509test.extensionObject(oid: .subjectKeyIdentifier) as? X509Certificate.SubjectKeyIdentifierExtension, let ski = ext_ski.value as? Data, let pk = x509test.publicKey, let pk_data = pk.key else { return ("Missing Subject Key Identifier of Reader Certificate", nil) }
		guard ski.bytes == Array(Insecure.SHA1.hash(data:pk_data))  else { return ("Wrong Subject Key Identifier of Reader Certificate", nil) }
		guard x509test.keyUsage.count > 0, x509test.keyUsage[0] else { return ("Key usage Digital Certificate should be mandatory", nil) }
		guard x509test.extendedKeyUsage.contains("1.0.18013.5.1.6") else { return ("Extended Key usage does not contain mdlReaderAuth", nil) }
		guard let ext_crl = x509test.extensionObject(oid: .cRLDistributionPoints) as? X509Certificate.CRLDistributionPointsExtension, let crls = ext_crl.crls, crls.count > 0 else { return ("Missing CRL Distribution extension", nil) }
		guard let ext_ocsp = x509test.extensionObject(oid: .authorityInfoAccess) as? X509Certificate.AuthorityInfoAccessExtension, let infoAccess = ext_ocsp.infoAccess, infoAccess.count > 0, infoAccess[0].method == "1.3.6.1.5.5.7.48.1", infoAccess[0].location.count > 0 else { return ("Missing extended OCSP extension", nil) }
		guard let algID = x509test.sigAlgOID, Self.ecdsaAlgOIDs.contains(algID) else { return ("Signature algorithm must be ECDSA with SHA 256/384/512", nil) }
		guard x509test.signature != nil else { return ("Missing Signature data", nil) }
		guard Set(x509test.criticalExtensionOIDs).intersection(Set(Self.nonAllowedExtensions)).count == 0 else { return ("Not allowed critical extension in cert.", nil) }
		guard let x509test2 = try? X509ExtAltName2(der: SecCertificateCopyData(secCert) as Data) else { return ("Issuer data not in cert.", nil) }
		guard let dan = x509test2.issuerAlternativeNamesAndTypes, dan.count > 0, dan[1] != nil || dan[6] != nil else { return ("Issuer data rfc822Name or uniformResourceIdentifier not in cert.", nil) }
		return (nil, dan)
	}
}
