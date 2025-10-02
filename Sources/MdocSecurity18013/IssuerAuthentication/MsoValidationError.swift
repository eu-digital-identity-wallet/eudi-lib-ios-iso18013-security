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

// IssuerAuthentication.swift
import Foundation
import SwiftCBOR
import MdocDataModel18013

/// Enumeration of possible validation errors when validating a Mobile Security Object (MSO)
public indirect enum MsoValidationError: LocalizedError, Sendable {
    case docTypeNotMatches
    case unsupportedDigestAlgorithm(String)
    case missingDigestValues(namespace: String, elementIdentifiers: [String])
    case invalidDigestValues(namespace: String, elementIdentifiers: [String])
    case signatureVerificationFailed(String)
    case validityInfo(String)
    case multipleErrors([MsoValidationError])

    public var errorDescription: String? {
        switch self {
        case .docTypeNotMatches:
            return NSLocalizedString("The document type does not match the expected value.", comment: "MsoValidationError")
        case .unsupportedDigestAlgorithm(let algorithm):
            return NSLocalizedString("The digest algorithm \(algorithm) is not supported.", comment: "MsoValidationError")
        case .missingDigestValues(let namespace, let elementIdentifiers):
            return NSLocalizedString("The digest values are missing for namespace '\(namespace)' elements \(elementIdentifiers.joined(separator: ", "))", comment: "MsoValidationError")
        case .invalidDigestValues(let namespace, let elementIdentifiers):
            return NSLocalizedString("The digest values for namespace '\(namespace)' elements \(elementIdentifiers.joined(separator: ", ")) are invalid.", comment: "MsoValidationError")
        case .signatureVerificationFailed(let reason):
            return NSLocalizedString("The MSO signature verification failed: \(reason)", comment: "MsoValidationError")
        case .validityInfo(let reason):
            return NSLocalizedString("MSO validity info check failed: \(reason)", comment: "MsoValidationError")
        case .multipleErrors(let errors):
            return NSLocalizedString("Multiple MSO validation errors occurred: \(errors.map { $0.errorDescription ?? "" }.joined(separator: "; "))", comment: "MsoValidationError")
        }
    }
}