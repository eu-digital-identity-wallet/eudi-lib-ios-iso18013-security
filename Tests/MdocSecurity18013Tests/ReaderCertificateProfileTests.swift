import CryptoKit
import Foundation
import SwiftASN1
import Testing
import X509

@testable import MdocSecurity18013

@Suite("Reader certificate profile")
struct ReaderCertificateProfileTests {
    // Each invalid certificate differs from a conforming profile in one property.
    @Test(arguments: [
        "issuer", "akiMissing", "akiEmpty", "akiMalformed",
        "skiMissing", "skiEmpty", "skiWrong", "skiMalformed",
        "kuMissing", "kuWrong", "kuMalformed",
        "ekuMissing", "ekuWrong", "ekuMalformed", "algorithm",
        "crlMissing", "crlEmpty", "crlMalformed", "critical"
    ])
    func rejectsProfileViolation(_ violation: String) throws {
        let certificate = try makeCertificate(violation: violation)
        var messages = [String]()
        let (valid, reason) = SecurityHelpers.verifyReaderAuthCert(certificate, messages: &messages)
        #expect(!valid, "Accepted profile violation: \(violation)")
        #expect(reason?.isEmpty == false)
    }

    @Test("Conforming reader profile accepts existing unrelated diagnostics")
    func acceptsConformingProfile() throws {
        var messages = ["An earlier diagnostic"]
        let (valid, reason) = SecurityHelpers.verifyReaderAuthCert(try makeCertificate(), messages: &messages)
        #expect(valid)
        #expect(reason == nil)
        #expect(messages == ["An earlier diagnostic"])
    }

    @Test("An anchored certificate for another purpose is rejected by the reader trust API")
    func rejectsOtherPurposeThroughTrustAPI() async throws {
        let leaf = try Data(contentsOf: #require(Bundle.module.url(forResource: "eudi-test-leaf", withExtension: "der")))
        let root = try Data(contentsOf: #require(Bundle.module.url(forResource: "eudi-test-root", withExtension: "der")))
        let reader = SecTrustSource(rootIaca: [[root]], usage: .mdocReaderAuth, revocationPolicy: .warning)
        let (valid, reason) = await reader.validateCertTrustPath(chain: [leaf])
        #expect(!valid)
        #expect(reason?.contains("mdlReaderAuth") == true)
        #expect(reason?.contains("ECDSA") == true)
        #expect(await reader.createCertTrustPath(chain: [leaf]) == nil)

        let issuer = SecTrustSource(rootIaca: [[root]], usage: .mdocAuth, revocationPolicy: .warning)
        #expect(await issuer.validateCertTrustPath(chain: [leaf]).0)
        #expect(await issuer.createCertTrustPath(chain: [leaf]) != nil)
    }

    @Test("A conforming reader leaf chains to its configured anchor")
    func acceptsReaderThroughTrustAPI() async throws {
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName("Reader test CA") }
        let root = try Certificate(
            version: .v3, serialNumber: 2, publicKey: .init(key.publicKey),
            notValidBefore: Date().addingTimeInterval(-3600),
            notValidAfter: Date().addingTimeInterval(3600), issuer: name, subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
            }, issuerPrivateKey: .init(key)
        )
        let leaf = try makeCertificate(issuerName: name, signingKey: key)
        var rootSerializer = DER.Serializer()
        try rootSerializer.serialize(root)
        var leafSerializer = DER.Serializer()
        try leafSerializer.serialize(leaf)
        let rootDER = Data(rootSerializer.serializedBytes)
        let leafDER = Data(leafSerializer.serializedBytes)
        let source = SecTrustSource(rootIaca: [[rootDER]], usage: .mdocReaderAuth, revocationPolicy: .warning)
        let (valid, reason) = await source.validateCertTrustPath(chain: [leafDER])
        #expect(valid, "\(reason ?? "")")
        #expect(reason == nil)
        #expect(await source.createCertTrustPath(chain: [leafDER]) == [leafDER, rootDER])
    }

    private func makeCertificate(
        violation: String? = nil,
        issuerName: DistinguishedName? = nil,
        signingKey: P256.Signing.PrivateKey? = nil
    ) throws -> Certificate {
        let key = P256.Signing.PrivateKey()
        let publicKey = Certificate.PublicKey(key.publicKey)
        let name = try DistinguishedName { CommonName("Reader profile test") }
        var extensions = [Certificate.Extension]()
        if violation != "akiMissing" {
            extensions.append(try Certificate.Extension(AuthorityKeyIdentifier(
                keyIdentifier: violation == "akiEmpty" ? [] :
                    Array(Insecure.SHA1.hash(data: Certificate.PublicKey((signingKey ?? key).publicKey).subjectPublicKeyInfoBytes))[...]
            ), critical: false))
        }
        if violation != "skiMissing" {
            let identifier: ArraySlice<UInt8>
            switch violation {
            case "skiEmpty": identifier = []
            case "skiWrong": identifier = [1, 2, 3]
            default: identifier = Array(Insecure.SHA1.hash(data: publicKey.subjectPublicKeyInfoBytes))[...]
            }
            extensions.append(try Certificate.Extension(SubjectKeyIdentifier(keyIdentifier: identifier), critical: false))
        }
        if violation != "kuMissing" {
            extensions.append(try Certificate.Extension(KeyUsage(digitalSignature: violation != "kuWrong"), critical: true))
        }
        if violation != "ekuMissing" {
            let usage: ExtendedKeyUsage.Usage = violation == "ekuWrong" ? .serverAuth : .init(oid: .extKeyUsageMdlReaderAuth)
            extensions.append(try Certificate.Extension(ExtendedKeyUsage([usage]), critical: false))
        }
        if violation != "crlMissing" {
            // DistributionPoint -> distributionPoint -> fullName -> URI.
            let uri = Array("https://example.invalid/reader.crl".utf8)
            let value: [UInt8] = violation == "crlEmpty" ? [0x30, 0] :
                [0x30, UInt8(uri.count + 8), 0x30, UInt8(uri.count + 6),
                 0xa0, UInt8(uri.count + 4), 0xa0, UInt8(uri.count + 2), 0x86, UInt8(uri.count)] + uri
            extensions.append(Certificate.Extension(oid: .X509ExtensionID.cRLDistributionPoints, critical: false, value: value[...]))
        }
        let malformedOIDs: [String: ASN1ObjectIdentifier] = [
            "akiMalformed": .X509ExtensionID.authorityKeyIdentifier,
            "skiMalformed": .X509ExtensionID.subjectKeyIdentifier,
            "kuMalformed": .X509ExtensionID.keyUsage,
            "ekuMalformed": .X509ExtensionID.extendedKeyUsage,
            "crlMalformed": .X509ExtensionID.cRLDistributionPoints
        ]
        if let violation, let oid = malformedOIDs[violation] {
            extensions.removeAll { $0.oid == oid }
            extensions.append(Certificate.Extension(oid: oid, critical: false, value: [0xff]))
        }
        if violation == "critical" {
            extensions.append(Certificate.Extension(oid: [2, 5, 29, 33], critical: true, value: [0x30, 0]))
        }
        let issuerKey: Certificate.PrivateKey = violation == "algorithm" ?
            .init(Curve25519.Signing.PrivateKey()) : .init(signingKey ?? key)
        return try Certificate(
            version: .v3, serialNumber: 1, publicKey: publicKey,
            notValidBefore: Date().addingTimeInterval(-3600),
            notValidAfter: Date().addingTimeInterval(3600),
            issuer: violation == "issuer" ? DistinguishedName() : (issuerName ?? name), subject: name,
            signatureAlgorithm: violation == "algorithm" ? .ed25519 : .ecdsaWithSHA256,
            extensions: Certificate.Extensions(extensions), issuerPrivateKey: issuerKey
        )
    }
}
