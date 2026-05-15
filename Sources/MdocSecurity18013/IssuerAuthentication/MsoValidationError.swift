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

// IssuerAuthentication.swift
import Foundation
import SwiftCBOR
import MdocDataModel18013

/// Enumeration of possible validation errors when validating a Mobile Security Object (MSO)
public indirect enum MsoValidationError: LocalizedError, Sendable {
    case docTypeNotMatches(String)
    case unsupportedDigestAlgorithm(String)
    case missingDigestValues(namespace: String, elementIdentifiers: [String])
    case invalidDigestValues(namespace: String, elementIdentifiers: [String])
    case signatureVerificationFailed(String)
    case validityInfo(String)
    case issuerTrustFailed(String)
    case multipleErrors([MsoValidationError])

    public var errorDescription: String? {
        switch self {
        case .docTypeNotMatches(let docType):
            let message = "The document type does not match the expected value '\(docType)' "
            return NSLocalizedString(message, comment: "MsoValidationError")
        case .unsupportedDigestAlgorithm(let algorithm):
            let message = "The digest algorithm \(algorithm) is not supported."
            return NSLocalizedString(message, comment: "MsoValidationError")
        case .missingDigestValues(let namespace, let elementIdentifiers):
            let missingElements = elementIdentifiers.joined(separator: ", ")
            let message = "The digest values are missing for namespace '\(namespace)' elements \(missingElements)"
            return NSLocalizedString(message, comment: "MsoValidationError")
        case .invalidDigestValues(let namespace, let elementIdentifiers):
            let invalidElements = elementIdentifiers.joined(separator: ", ")
            let message = "The digest values for namespace '\(namespace)' elements \(invalidElements) are invalid."
            return NSLocalizedString(message, comment: "MsoValidationError")
        case .signatureVerificationFailed(let reason):
            return NSLocalizedString("The MSO signature verification failed: \(reason)", comment: "MsoValidationError")
        case .validityInfo(let reason):
            return NSLocalizedString("MSO validity info check failed: \(reason)", comment: "MsoValidationError")
        case .issuerTrustFailed(let reason):
            return NSLocalizedString("MSO issuer trust check failed: \(reason)", comment: "MsoValidationError")
        case .multipleErrors(let errors):
            let joinedErrors = errors.map { $0.errorDescription ?? "" }.joined(separator: "; ")
            let message = "Multiple MSO validation errors occurred: \(joinedErrors)"
            return NSLocalizedString(message, comment: "MsoValidationError")
        }
    }
}