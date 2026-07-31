/*
Copyright (c) 2023-2026 European Commission

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
import Security

/// Interface that defines a trust manager, used to check the validity of a
/// document signer and the associated certificate chain. 
public protocol CertificateTrustValidator: Sendable {
    /// The document type this validator is currently operating on. Used to resolve the trust context appropriate for the document being validated.
    var docType: String? { get set }

    /// Creates a certification trust path by finding a certificate in the trust store
    /// that is the issuer of a certificate in the certificate chain.
    /// Returns `nil` if no trusted certificate can be found.
    ///
    /// - Parameter chain: DER-encoded certificates, leaf certificate first, followed by any
    ///   certificate that signed the previous certificate.
    /// - Returns: the certification path as DER-encoded certificates in the same order, or `nil`
    ///   if no certification trust path could be created.
    func createCertTrustPath(chain: [Data]) async -> [Data]?

    /// Validates that the given certificate chain is a valid chain that includes a document
    /// signer. Accepts a chain of certificates, starting with the document signer certificate,
    /// followed by any intermediate certificates up to the optional root certificate.
    ///
    /// The trust manager should be initialized with a set of trusted certificates. The chain
    /// is trusted if a trusted certificate can be found that has signed any certificate in the
    /// chain. The trusted certificate itself will be validated as well.
    ///
    /// - Parameter chain: the DER-encoded document signer, intermediate
    ///   certificates and optional root certificate.
    /// - Returns: a tuple whose first element is `false` if no trusted certificate could be found
    ///   for the certificate chain or if the certificate chain is invalid for any reason, and whose
    ///   second element is a human-readable failure reason when validation did not succeed (or `nil`).
    func validateCertTrustPath(chain: [Data]) async -> (Bool, String?)
}

// MARK: - SecCertificate convenience

public extension CertificateTrustValidator {
    /// Convenience overload of `createCertificationTrustPath(chain:)` that accepts a chain of
    /// `SecCertificate`s (leaf first).
    ///
    /// - Parameter chain: certificates, leaf certificate first.
    /// - Returns: the certification path in the same order, or `nil` if no trust path could be
    ///   created (including when any returned DER cannot be decoded into a certificate).
    func createCertTrustPath(chain: x5chain) async -> x5chain? {
        let derChain = chain.map { SecCertificateCopyData($0) as Data }
        guard let derPath = await createCertTrustPath(chain: derChain) else { return nil }
        let path = derPath.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard path.count == derPath.count else { return nil }
        return path
    }

    /// Convenience overload of `validateCertificationTrustPath(x5chain:)` that
    /// accepts a chain of `SecCertificate`s (document signer first).
    ///
    /// - Parameter x5chain: the document signer, intermediate certificates and
    ///   optional root certificate.
    /// - Returns: a tuple whose first element is `false` if no trusted certificate could be found
    ///   or the chain is invalid, and whose second element is a human-readable failure reason when
    ///   validation did not succeed (or `nil`).
    func validateCertTrustPath(chain: x5chain) async -> (Bool, String?) {
        let derChain = chain.map { SecCertificateCopyData($0) as Data }
        return await validateCertTrustPath(chain: derChain)
    }
}
