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

#if canImport(JSONWebSignature)
import Foundation
import MdocDataModel18013
import Security
import JSONWebSignature
import SwiftCBOR

/// Signature verification for JWT and CWT tokens carrying a certificate chain.
/// Use `validateTrust(_:trustValidator:)` to verify both the signature and the chain.
public final class x5cVerifyJwtOrCwt: @unchecked Sendable {
    public static let shared = x5cVerifyJwtOrCwt()
    nonisolated(unsafe) public static let compactJWSRegex = #/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/#

    public init() {}

    /// Verify the JWS signature against the leaf certificate carried in the `x5c` header,  using the `jose-swift` `JWS` implementation.
    /// `jose-swift` selects the verification algorithm from the JWS `alg` header and supports the
    /// ECDSA (`ES256` / `ES384` / `ES512`) and RSASSA-PKCS1-v1_5 (`RS256` / `RS384` / `RS512`)
    /// schemes used by the EUDI trust lists.
    /// - Throws: `JWS.JWSError` when the token is malformed, the verifying key is missing, or the
    ///   signature is invalid. Parse and verification failures are propagated from `jose-swift`.
    public static func verify(jws: JWS) throws {
        // RFC 7518, section 3.6: implementations MUST NOT accept Unsecured JWSs by default.
        if jws.protectedHeader.algorithm?.rawValue == "none" {
            throw JWS.JWSError.unsupportedAlgorithm(algorithm: "none")
        }
        // x5c entries are base64 (standard, not base64url) DER certificates; the leaf is first.
        guard let leafBase64 = jws.protectedHeader.x509CertificateChain?.first,
              let certData = Data(base64Encoded: leafBase64) else {
            throw JWS.JWSError.missingKey
        }
        // Extract the leaf certificate public key; `jose-swift` verifies against it via `SecKey`.
        guard let certificate = SecCertificateCreateWithData(nil, certData as CFData),
              let publicKey = SecCertificateCopyKey(certificate) else {
            throw JWS.JWSError.missingKey
        }
        // `verify(key:)` picks the algorithm from the header and throws `JWS.JWSError` on failure.
        guard try jws.verify(key: publicKey) else {
            throw JWS.JWSError.somethingWentWrong
        }
    }
    
    public static func parse(attestData: Data, format: AttestToken.Format?) throws -> AttestToken {
        let text = String(data: attestData, encoding: .ascii)?.trimmingCharacters(in: .whitespaces) ?? ""
        if (format == nil && text.wholeMatch(of: compactJWSRegex) != nil) || format == .jwt {
            guard let jwtString = String(data: attestData, encoding: .utf8) else { throw JWS.JWSError.invalidString }
            let jws = try JWS(jwsString: jwtString)
            return .jwt(jws)
        } else {
            let readerAuth = try ReaderAuth(data: [UInt8](attestData))
            return .cwt(readerAuth)
        }
    }

    /// CWT authentication failures are thrown separately from certificate-chain trust results.
    public enum CwtVerificationError: Error {
        case invalidStructure
        case unsupportedAlgorithm
        case missingKey
        case invalidSignature
    }

    private static func verify(cwt readerAuth: ReaderAuth) throws {
        let cose = readerAuth.coseSign1
        guard cose.type == .sign1,
              case let .byteString(headerBytes) = cose.protectedHeader.rawHeader,
              case let .map(headers) = try CBOR.decode(headerBytes),
              case let .byteString(payload) = cose.payload else {
            throw CwtVerificationError.invalidStructure
        }
        // Check the signed algorithm's CBOR type as well as its value. The model's
        // algorithm accessor alone does not distinguish positive and negative integers.
        guard case let .negativeInt(algorithm) = headers[.unsignedInt(1)],
              Cose.VerifyAlgorithm(rawValue: algorithm) != nil else {
            throw CwtVerificationError.unsupportedAlgorithm
        }
        guard let leaf = readerAuth.x5chain.first,
              let publicKey = SecurityHelpers.getPublicKeyx963(publicCertData: Data(leaf)) else {
            throw CwtVerificationError.missingKey
        }
        // Preserve the original protected-header bytes when constructing Sig_structure.
        // CryptoKit also rejects malformed signatures and keys incompatible with the algorithm.
        guard !cose.signature.isEmpty,
              try cose.validateDetachedCoseSign1(payloadData: Data(payload), publicKey_x963: publicKey) else {
            throw CwtVerificationError.invalidSignature
        }
    }

    /// Authenticates the token signature, then evaluates its certificate chain.
    /// Signature/format failures throw for both formats; only chain-trust failures
    /// are returned as `false`, so warning policies cannot downgrade invalid signatures.
    /// CWTs must contain an embedded byte-string payload and a supported protected ECDSA algorithm.
    public static func validateTrust(_ attestToken: AttestToken, trustValidator: CertificateTrustValidator) async throws -> (Bool, String?) {
        let certsData: [Data]
        switch attestToken {
        case let .jwt(jws):
            try Self.verify(jws: jws)
            guard let b64certs = jws.protectedHeader.x509CertificateChain else { throw JWS.JWSError.somethingWentWrong }
            certsData = b64certs.compactMap { Data(base64Encoded: $0) }
            guard certsData.count == b64certs.count else { throw JWS.JWSError.somethingWentWrong }
        case let .cwt(readerAuth):
            try Self.verify(cwt: readerAuth)
            certsData = readerAuth.x5chain.map { Data($0) }
        }
        guard certsData.count > 0 else { throw JWS.JWSError.somethingWentWrong }
        return await trustValidator.validateCertTrustPath(chain: certsData)
    }
}
#endif


