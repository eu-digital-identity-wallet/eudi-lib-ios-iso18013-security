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
import MdocDataModel18013
import SwiftCBOR
import X509

extension IssuerSigned {
    public func validateMSO(docType: String, trustedIACA: [SecCertificate]) throws(MsoValidationError) {
        // Perform validation logic here
        let msoValidationRules: [(MobileSecurityObject) -> [MsoValidationError]?] =
            [
                { if $0.docType == docType { nil } else { [.docTypeNotMatches($0.docType)] } },
                { if DigestAlgorithmKind(rawValue: $0.digestAlgorithm) != nil { nil } else { [.unsupportedDigestAlgorithm($0.digestAlgorithm)] } },
                { validateDigestValues(mso: $0) },
                { validateValidityInfo(mso: $0) },
                { _ in validateMsoSignature() },
                { _ in validateTrustedIACA(trustedIACA) }
            ]
        let errors: [MsoValidationError] = msoValidationRules.compactMap { $0(issuerAuth.mso) }.flatMap { $0 }
        if !errors.isEmpty {
            throw if errors.count == 1, let first = errors.first { first } else { .multipleErrors(errors) }
        }
    }

    // Validate the digest values in the MSO against the actual data elements
    func validateDigestValues(mso: MobileSecurityObject) -> [MsoValidationError]? {
        var errorList: [MsoValidationError] = []
        guard let nsItems = issuerNameSpaces?.nameSpaces,
        let dak = DigestAlgorithmKind(rawValue: mso.digestAlgorithm) else { return nil }
        for (ns,items) in nsItems {
          let result = validateDigests(for: ns, items: items, dak: dak, mso: mso)
            if !result.missing.isEmpty {
                errorList.append(.missingDigestValues(namespace: ns, elementIdentifiers: result.missing))
            }
            if !result.failed.isEmpty {
                errorList.append(.invalidDigestValues(namespace: ns, elementIdentifiers: result.failed))
            }
        }
        return if errorList.isEmpty {nil } else { errorList }
    }

    func validateValidityInfo(mso: MobileSecurityObject) -> [MsoValidationError]? {
        guard !issuerAuth.x5chain.isEmpty, let dsCert = try? X509.Certificate(derEncoded: issuerAuth.x5chain[0]) else { return [.signatureVerificationFailed("No issuer certificates provided in x5chain")] }
        guard let sd = mso.validityInfo.signed.convertToLocalDate(), let vf = mso.validityInfo.validFrom.convertToLocalDate(), let vu = mso.validityInfo.validUntil.convertToLocalDate() else { return [.validityInfo("MSO validity contains invalid strings")]}
        var errorList: [MsoValidationError] = []
        if !(sd >= dsCert.notValidBefore && sd <= dsCert.notValidAfter) { errorList.append(.validityInfo("The 'signed' date is not within the validity period of the certificate in the MSO: \(sd.formatted()) (\(dsCert.notValidBefore.formatted()) - \(dsCert.notValidAfter.formatted()))")) }
		if !(vf <= .now && vf <= vu) { errorList.append(.validityInfo("Current timestamp is not equal or later than the ‘validFrom’ element: \(vf.formatted())")) }
		if !(vu >= .now) { errorList.append(.validityInfo("Current timestamp is not less than the ‘validUntil’ element: \(vu.formatted())")) }
        return errorList.isEmpty ? nil : errorList
    }

    // Verify the MSO signature using the ds certificate in x5chain
    func validateMsoSignature() -> [MsoValidationError]? {
        guard !issuerAuth.x5chain.isEmpty else { return [.signatureVerificationFailed("No issuer certificates provided in x5chain")] }
        let chain = issuerAuth.x5chain.compactMap { try? X509.Certificate(derEncoded: $0) }
        guard chain.count == issuerAuth.x5chain.count else { return [.signatureVerificationFailed("Invalid issuer certificate in x5chain")] }
        // check all certificates are not iaca
        for cert in chain {
            if cert.issuer == cert.subject { return [.signatureVerificationFailed("Certificate in x5chain is a IACA certificate, expected end-entity certificate")] }
        }
        // Get the first certificate from the chain (the issuer certificate)
        let dsCertData = Data(issuerAuth.x5chain[0])
        // Extract the public key from the certificate
        guard let publicKey = SecurityHelpers.getPublicKeyx963(publicCertData: dsCertData) else {
            return [.signatureVerificationFailed("Failed to extract public key from issuer certificate")]
        }
        // Create a COSE structure for validation
        let cose = Cose(type: .sign1, algorithm: issuerAuth.verifyAlgorithm.rawValue, signature: issuerAuth.signature)
        // Validate the signature
        do {
            let isValid = try cose.validateDetachedCoseSign1(payloadData: Data(issuerAuth.msoRawData), publicKey_x963: publicKey)
            if !isValid { return [.signatureVerificationFailed("Issuer authentication signature validation failed")] }
        } catch {
            return [.signatureVerificationFailed("Signature validation error: \(error.localizedDescription)")]
        }
        return nil
    }

    // Validate the issuer certificate against a list of trusted IACA certificates
    func validateTrustedIACA(_ trustedIACA: [SecCertificate]) -> [MsoValidationError]? {
        let secCerts = issuerAuth.x5chain.compactMap { SecCertificateCreateWithData(nil, Data($0) as CFData) }
        guard secCerts.count > 0, secCerts.count == issuerAuth.x5chain.count else { return [.signatureVerificationFailed("Invalid issuer certificates in x5chain")] }
        let b2 = SecurityHelpers.isMdocX5cValid(secCerts: secCerts, usage: .mdocAuth, rootCerts: trustedIACA)
        if !b2.isValid {
            let reasons = b2.validationMessages.joined(separator: "; ")
            return [.issuerTrustFailed("Issuer certificate validation failed: \(reasons)")]
        }
        return nil
    }

}
