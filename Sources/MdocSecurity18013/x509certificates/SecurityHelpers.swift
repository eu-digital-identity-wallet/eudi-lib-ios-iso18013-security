/*
Copyright (c) 2026 European Commission

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

public typealias x5chain = [SecCertificate]

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

	public static func isMdocX5cValid(
		secCerts: x5chain,
		usage: CertificateUsage,
		rootIaca: [x5chain]
	) -> (isValid: Bool, validationMessages: [String], rootCert: SecCertificate?) {
		guard let secCert = secCerts.first else { return (false, ["Certificate not found"], nil) }
		// convert to swift-certificates object
		guard let x509cert = try? secCert.certificate() else { return (false,["Not valid certificate for \(usage)"], nil) }
		let now = Date()
		var messages = [String]()
		var trust: SecTrust?
		let policy = SecPolicyCreateBasicX509()
		_ = SecTrustCreateWithCertificates(secCerts as CFArray, policy, &trust)
		guard let trust else { return (false, ["Not valid certificate for \(usage)"], nil) }
		let certificateValidityRange = "\(x509cert.notValidBefore.formatted()) - \(x509cert.notValidAfter.formatted())"
		let certificateValidityMessage = "Current date not in validity period of Certificate: \(certificateValidityRange)"
		guard x509cert.notValidBefore <= now, now <= x509cert.notValidAfter else {
			return (false, [certificateValidityMessage], nil)
		}
		let valDays = Calendar.current.dateComponents([.day], from: x509cert.notValidBefore, to: x509cert.notValidAfter).day
		guard let valDays, valDays >= 0 else { return (false, ["Invalid validity period"], nil) }
		guard !x509cert.subject.isEmpty,
			  let commonName = getCommonName(ref: secCert),
			  !commonName.isEmpty else {
			return (false, ["Missing Common Name of Reader Certificate"], nil)
		}
		guard !x509cert.signature.description.isEmpty else { return (false, ["Missing Signature data"], nil) }
		if x509cert.serialNumber.description.isEmpty { messages.append("Missing Serial number") }
		guard !x509cert.hasDuplicateExtensions() else { return (false, ["Duplicate extensions in Certificate"], nil) }
		if usage == .mdocReaderAuth {
			let (isValidExt, extError) = verifyReaderAuthCert(x509cert, messages: &messages)
			if !isValidExt { return (false, [extError ?? "Certificate extension validation failed"], nil) }
			if let gns = x509cert.getSubjectAlternativeNames(),
			   let preferredGeneralName = gns.first(where: {
				switch $0 {
				case .rfc822Name(_), .uniformResourceIdentifier(_):
					return true
				default:
					return false
				}
			   }) {
				logger.info("Alternative name \(preferredGeneralName.description)")
			}
		}
		SecTrustSetPolicies(trust, policy)
		for rootChain in rootIaca {
			guard let rootCert = rootChain.last else { continue }
			SecTrustSetAnchorCertificates(trust, rootChain as CFArray)
			SecTrustSetAnchorCertificatesOnly(trust, true)
			let (serverTrustIsValid, errorMessage, errorCode) = trustIsValid(trust)
			if let errorMessage { messages.append("Trust evaluation error: \(errorMessage) (code: \(errorCode ?? -1))") }
			if serverTrustIsValid {
				guard let x509root = try? rootCert.certificate() else { return (false, ["Bad root certificate"], rootCert) }
				guard x509root.notValidBefore <= now, now <= x509root.notValidAfter else {
					return (false, ["Current date not in validity period of Reader Root Certificate"], nil)
				}
				if usage == .mdocReaderAuth,
				   let rootGeneralNames = x509root.getSubjectAlternativeNames(),
				   let certificateGeneralNames = x509cert.getSubjectAlternativeNames() {
					guard certificateGeneralNames.elementsEqual(rootGeneralNames) else {
						return (false, ["Issuer data rfc822Name or uniformResourceIdentifier do not match with root cert."], nil)
					}
				}
				let bs = fetchCRLSerialNumbers(x509root, messages: &messages)
				if !bs.isEmpty {
					if bs.contains(x509cert.serialNumber) { return (false, ["Revoked issued Certificate"], rootCert)}
					if bs.contains(x509root.serialNumber) { return (false,["Revoked Root Certificate"], rootCert)}
				}
				return (true, messages, rootCert)
			}
		} // next
		messages.insert("Certificate not matched with root certificates", at: 0)
		return (false, messages, nil)
	}

	public static func trustIsValid(_ trust: SecTrust) -> (Bool, String?, Int?) {
		var error: CFError?
		let isValid = SecTrustEvaluateWithError(trust, &error)
		//if let error { logger.error("Error evaluating trust: \(error)") }
        return (isValid, error?.localizedDescription, (error as? NSError)?.code)
	}

	public static func isChainFound(
		secCerts: x5chain,
		rootIaca: [x5chain]
	) async -> (isValid: Bool, validationMessages: [String], rootCert: SecCertificate?) {
        var validationMessages: [String] = []
        guard let leafSecCert = secCerts.first, let leafCert = try? leafSecCert.certificate() else {
            return (false, ["Certificate not found"], nil)
        }
        let intermediateCerts: [Certificate] = secCerts.dropFirst().compactMap { try? $0.certificate() }
        for rootChain in rootIaca {
            guard let rootSecCert = rootChain.last else { continue }
            let rootCerts = rootChain.compactMap { try? $0.certificate() }
            guard !rootCerts.isEmpty else { continue }
			let (isValid, messages) = await verifyChain(
				rootCertificates: rootCerts,
				intermediateCertificates: intermediateCerts,
				leafCertificate: leafCert
			)
            if isValid { return (true, messages, rootSecCert) } else { validationMessages = messages }
        }
        return (false, ["Certificate chain not matched with root certificates"] + validationMessages, nil)
    }

	public static func verifyChain(
		rootCertificates: [Certificate],
		intermediateCertificates: [Certificate] = [],
		leafCertificate: Certificate
	) async -> (Bool, [String]) {
    let roots = CertificateStore(rootCertificates)
    var verifier = Verifier(rootCertificates: roots) {
      AnyPolicy {
        RFC5280Policy()
      }
    }
    let result = await verifier.validate(
      leaf: leafCertificate,
      intermediates: CertificateStore(intermediateCertificates)) { diagnostic in
    }
    switch result {
    case .validCertificate:
      return (true, [])
    case .couldNotValidate(let policyFailures):
      return (false, policyFailures.map { $0.policyFailureReason.description })
    }
  }

	public static func fetchCRLSerialNumbers(
		_ x509root: X509.Certificate,
		messages: inout [String]
	) -> [Certificate.SerialNumber] {
		var bs = [Certificate.SerialNumber]()
		if let crlDistributionExtension = x509root.extensions[oid: .X509ExtensionID.cRLDistributionPoints],
		   let crlDistributions = try? CRLDistributions(derEncoded: crlDistributionExtension.value) {
			for crl in crlDistributions.crls {
				guard let crlUrl = URL(string: crl.distributionPoint) else { continue }
				guard let crlData = try? Data(contentsOf: crlUrl) else { continue }
				let crl: CRL
				if let pemString = String(data: crlData, encoding: .utf8), pemString.contains("-----BEGIN") {
					guard let pemCrl = try? CRL(pemEncoded: pemString) else { continue }
					crl = pemCrl
				} else {
					guard let derCrl = try? CRL(derEncoded: Array(crlData)) else { continue }
					crl = derCrl
				}
				guard crl.isValid else {
					let validityWindow = "thisUpdate: \(crl.thisUpdate), nextUpdate: \(crl.nextUpdate)"
					let errorMessage = "CRL from \(crlUrl) is not within its validity period (\(validityWindow))"
					messages.append(errorMessage)
					continue
				}
				guard crl.verifySignature(issuer: x509root) else {
					messages.append("CRL from \(crlUrl) has an invalid signature")
					continue
				}
				bs.append(contentsOf: crl.revokedSerials.map(\.serial))
			}
		}
		return bs
	}

	/// Verify reader auth certificate extensions and properties.
	/// - Returns: A tuple of (isValid, errorMessage). If isValid is false, validation must fail.
	@discardableResult
	public static func verifyReaderAuthCert(_ x509: X509.Certificate, messages: inout [String]) -> (Bool, String?) {
		// check issuer
		if !x509.issuer.isEmpty {
			logger.info("Issuer \(x509.issuer.description)")
		} else {
			messages.append("Missing Issuer")
		}
		// check authority key identifier
		if let authorityKeyIdentifier = try? x509.extensions.authorityKeyIdentifier,
		   let keyIdentifier = authorityKeyIdentifier.keyIdentifier,
		   !keyIdentifier.isEmpty {
			logger.notice("Authority key identifier \(keyIdentifier.description)")
		} else {
			messages.append("Missing Authority Key Identifier")
		}
		// check subject key identifier
		let publicKeyData = Array(x509.publicKey.subjectPublicKeyInfoBytes)
		let subjectKeyIdentifierExtension = try? x509.extensions.subjectKeyIdentifier
		if let subjectKeyIdentifierExtension {
			logger.notice("Subject key Identifier \(subjectKeyIdentifierExtension.keyIdentifier.description)")
			let subjectKeyIdentifier = Array(subjectKeyIdentifierExtension.keyIdentifier)
			let expectedKeyIdentifier = Array(Insecure.SHA1.hash(data: publicKeyData))
			if subjectKeyIdentifier == expectedKeyIdentifier {
				logger.info("Subject Key Identifier equal to public key SHA1")
			} else {
				messages.append("Wrong Subject Key Identifier")
			}
		} else { messages.append("Missing Subject Key Identifier") }
		// check key usage
		if let keyUsage = try? x509.extensions.keyUsage, keyUsage.digitalSignature {
			logger.info("Subject public key is used for verifying Digital Signature")
		} else {
			messages.append("Key usage should be verifying Digital Certificate")
		}
		// check extended key usage
		if let extKeyUsage = try? x509.extensions.extendedKeyUsage,
		   extKeyUsage.contains(ExtendedKeyUsage.Usage(oid: .extKeyUsageMdlReaderAuth)) {
			logger.info("Extended key usage contains mdlReaderAuth")
		} else {
			messages.append("Extended Key usage does not contain mdlReaderAuth")
		}
		// display extended OCSP extension
		if let authorityInformationAccess = try? x509.extensions.authorityInformationAccess,
		   let infoAccesses = authorityInformationAccess.infoAccesses,
		   let ocspAccess = infoAccesses.first,
		   ocspAccess.method == .ocspServer,
		   !ocspAccess.location.description.isEmpty {
			logger.info("OCSP server location: \(ocspAccess.location.description)")
		}
		if x509.signatureAlgorithm.isECDSA256or384or512 {
			logger.info("Signature algorithm is \(x509.signatureAlgorithm)")
		} else {
			messages.append("Signature algorithm must be ECDSA with SHA 256/384/512")
		}
		// check for not allowed critical extensions — must cause validation failure per RFC 5280 Section 4.2
		let criticalExtensionOIDs: [String] = x509.extensions.filter(\.critical).map(\.oid).map(\.description)
		let notAllowedCriticalExt = Set(criticalExtensionOIDs).intersection(Set(Self.nonAllowedExtensions))
		if notAllowedCriticalExt.isEmpty {
			logger.info("Critical extensions correct")
		} else {
			return (false, "Not allowed critical extensions \(notAllowedCriticalExt)")
		}
		// check crls existing
		if let crlDistributionExtension = x509.extensions[oid: .X509ExtensionID.cRLDistributionPoints],
		   let crlDistributionPoints = try? CRLDistributionPointsExtension(crlDistributionExtension),
		   !crlDistributionPoints.crls.isEmpty,
		   crlDistributionPoints.crls.allSatisfy(\.isNotEmpty) {
			logger.info("CRL Distribution extension found")
		} else {
			messages.append("Missing CRL Distribution extension")
		}
		return (true, nil)
	}

	public static func getCommonName(ref: SecCertificate) -> String? {
		var cfName: CFString?
		SecCertificateCopyCommonName(ref, &cfName)
		return cfName as String?
	}
}


