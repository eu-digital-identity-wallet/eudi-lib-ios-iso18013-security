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
public enum MsoValidationError: LocalizedError, Sendable {
    /// The digest algorithm is not supported
    case unsupportedDigestAlgorithm
    /// The digest value is missing
    case missingDigestValue
    /// The digest value does not match the calculated value
    case invalidDigestValue(namespace: String)

    public var errorDescription: String? {
        switch self {
        case .unsupportedDigestAlgorithm:
            return NSLocalizedString("The digest algorithm is not supported.", comment: "MsoValidationError")
        case .missingDigestValue:
            return NSLocalizedString("The digest value is missing.", comment: "MsoValidationError")
        case .invalidDigestValue(let namespace):
            return NSLocalizedString("The digest value for namespace '\(namespace)' is invalid.", comment: "MsoValidationError")
        }
    }
}