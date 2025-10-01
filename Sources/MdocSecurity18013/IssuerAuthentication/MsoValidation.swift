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

import ValidationKit

extension IssuerSigned {
    public func validateMSO(docType: String) -> (Bool, [MsoValidationError]) {
        // Perform validation logic here
        let msoValidationRules: [(MobileSecurityObject) -> [MsoValidationError]?] =
            [
                { if $0.docType == docType { nil } else { [.docTypeNotMatches] } },
                { if DigestAlgorithmKind(rawValue: $0.digestAlgorithm) != nil { nil } else { [.unsupportedDigestAlgorithm($0.digestAlgorithm)] } },
                { self.validateDigestValues(mso: $0) }
            ]
        let errors: [MsoValidationError] = msoValidationRules.compactMap { $0(issuerAuth.mso) }.flatMap { $0 }
        return (errors.isEmpty, errors)
    }

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

}
