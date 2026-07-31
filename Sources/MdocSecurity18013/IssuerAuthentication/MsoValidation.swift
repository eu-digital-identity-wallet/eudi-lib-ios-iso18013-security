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
import MdocDataModel18013
import SwiftCBOR
import X509

extension IssuerSigned {
    public func validate(
        docType: String,
        trustValidator: (any CertificateTrustValidator),
        trustPolicy: TrustPolicy,
        rejectIfValidUntilExceedsCertificateValidity: Bool = false,
        publicCoseKeys: inout [CoseKey]
    ) async throws(MsoValidationError) {
        // Perform validation logic here
        let msoValidationRules: [(MobileSecurityObject) -> [MsoValidationError]?] =
            [
                { if $0.docType == docType { nil } else { [.docTypeNotMatches($0.docType)] } },
                { if DigestAlgorithmKind(rawValue: $0.digestAlgorithm) != nil { nil } else { [.unsupportedDigestAlgorithm($0.digestAlgorithm)] } },
                { validateDigestValues(mso: $0) },
            ]
        var errors: [MsoValidationError] = msoValidationRules.compactMap { $0(issuerAuth.mso) }.flatMap { $0 }
        let dsCertificate = resolveDocumentSignerCertificate()
        if let validityErrors = validateValidityInfo(mso: issuerAuth.mso, rejectIfValidUntilExceedsCertificateValidity, dsCertificate: dsCertificate) {
            errors.append(contentsOf: validityErrors)
        }
        if let trustErrors = await validateIssuerTrust(trustValidator: trustValidator) {
            if trustPolicy == .enforce { errors.append(contentsOf: trustErrors) }
        }
        let bindingKeyErrors = validateMsoSignature(publicCoseKeys: &publicCoseKeys)
        if let bindingKeyErrors { errors.append(contentsOf: bindingKeyErrors)}
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

    /// Resolves the document-signer certificate from the first certificate in x5chain.
    func resolveDocumentSignerCertificate() -> X509.Certificate? {
        guard !issuerAuth.x5chain.isEmpty else { return nil }
        return try? X509.Certificate(derEncoded: issuerAuth.x5chain[0])
    }

    /// Validates the issuer certificate chain against the trust validator, returning an
    /// `.issuerTrustFailed` error carrying the validator's failure reason when the chain is
    /// not trusted. Returns `nil` when no trust validator is provided or the chain is trusted.
    func validateIssuerTrust(
        trustValidator: (any CertificateTrustValidator)
    ) async -> [MsoValidationError]? {
        guard !issuerAuth.x5chain.isEmpty else {
            return [.issuerTrustFailed("No issuer certificates provided in x5chain")]
        }
        let (trusted, failureReason) = await trustValidator.validateCertTrustPath(chain: issuerAuth.x5chain.map { Data($0) })
        guard trusted else {
            return [.issuerTrustFailed(failureReason ?? "The issuer certificate chain is not trusted")]
        }
        return nil
    }

    func validateValidityInfo(
        mso: MobileSecurityObject,
        _ rejectIfValidUntilExceedsCertificateValidity: Bool = false,
        dsCertificate: X509.Certificate? = nil
    ) -> [MsoValidationError]? {
        let resolvedCert = dsCertificate
            ?? (issuerAuth.x5chain.isEmpty ? nil : try? X509.Certificate(derEncoded: issuerAuth.x5chain[0]))
        guard let dsCert = resolvedCert else {
            return [.signatureVerificationFailed("No issuer certificates provided in x5chain")]
        }
        guard let signedDate = mso.validityInfo.signed.convertToLocalDate(),
              let validFromDate = mso.validityInfo.validFrom.convertToLocalDate(),
              let validUntilDate = mso.validityInfo.validUntil.convertToLocalDate() else {
            return [.validityInfo("MSO validity contains invalid strings")]
        }
        var errorList: [MsoValidationError] = []
        if !(signedDate >= dsCert.notValidBefore && signedDate <= dsCert.notValidAfter) {
            let validityRange = "\(dsCert.notValidBefore.formatted()) - \(dsCert.notValidAfter.formatted())"
            let signedDateIssue = "The 'signed' date is not within the validity period"
            let message = "\(signedDateIssue) of the certificate in the MSO: "
                + "\(signedDate.formatted()) (\(validityRange))"
            errorList.append(.validityInfo(message))
        }
        if !(validFromDate <= .now.addingTimeInterval(60)) {
            let validFromIssue = "Current timestamp is not equal or later than the ‘validFrom’ element"
            let message = "\(validFromIssue): \(validFromDate.formatted())"
            errorList.append(.validityInfo(message))
        }
        if !(validFromDate < validUntilDate) {
            let orderIssue = "The ‘validFrom’ element must be strictly earlier than the ‘validUntil’ element"
            let message = "\(orderIssue): \(validFromDate.formatted()) >= \(validUntilDate.formatted())"
            errorList.append(.validityInfo(message))
        }
        if !(validUntilDate.addingTimeInterval(60) >= .now) {
            let message = "Current timestamp is not less than the ‘validUntil’ element: \(validUntilDate.formatted())"
            errorList.append(.validityInfo(message))
        }
        if rejectIfValidUntilExceedsCertificateValidity && validUntilDate > dsCert.notValidAfter {
            let certificateOverflowIssue = "The ‘validUntil’ element exceeds certificate validity"
            let certificateLimit = dsCert.notValidAfter.formatted()
            let message = "\(certificateOverflowIssue): \(validUntilDate.formatted()) > \(certificateLimit)"
            errorList.append(.validityInfo(message))
        }
        return errorList.isEmpty ? nil : errorList
    }

    // Verify the MSO signature using the ds certificate in x5chain
    func validateMsoSignature(publicCoseKeys: inout [CoseKey]) -> [MsoValidationError]? {
        guard !issuerAuth.x5chain.isEmpty else {
            return [.signatureVerificationFailed("No issuer certificates provided in x5chain")]
        }
        let chain = issuerAuth.x5chain.compactMap { try? X509.Certificate(derEncoded: $0) }
        guard chain.count == issuerAuth.x5chain.count else {
            return [.signatureVerificationFailed("Invalid issuer certificate in x5chain")]
        }
        // Get the first certificate from the chain (the issuer certificate)
        let dsCertData = Data(issuerAuth.x5chain[0])
        // Extract the public key from the certificate
        guard let issuerPublicKey = SecurityHelpers.getPublicKeyx963(publicCertData: dsCertData) else {
            return [.signatureVerificationFailed("Failed to extract public key from issuer certificate")]
        }
        // If public COSE keys given to the issuer are provided in options,
        // check if the device public key matches any of them.
        let deviceKey = issuerAuth.mso.deviceKeyInfo.deviceKey.x963Representation
        let publicCoseKeyData = publicCoseKeys.map(\.x963Representation)
        let coseIndex = publicCoseKeyData.firstIndex(of: deviceKey)
        if let coseIndex {
            publicCoseKeys.remove(at: coseIndex)
        } else {
            return [
                .signatureVerificationFailed(
                    "Device key does not match any of the provided public COSE keys"
                )
            ]
        }
        // Create a COSE structure for validation
        let cose = Cose(type: .sign1, algorithm: issuerAuth.verifyAlgorithm.rawValue, signature: issuerAuth.signature)
        // Validate the signature
        do {
            let isValid = try cose.validateDetachedCoseSign1(
                payloadData: Data(issuerAuth.msoRawData),
                publicKey_x963: issuerPublicKey
            )
            if !isValid { return [.signatureVerificationFailed("Issuer authentication signature validation failed")] }
        } catch {
            return [.signatureVerificationFailed("Signature validation error: \(error.localizedDescription)")]
        }
        return nil
    }

}
