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
import Testing
import X509
import Security

@testable import MdocDataModel18013
@testable import MdocSecurity18013

@Suite("Certificate Handling Tests")
struct CertificateHandlingTests {
    var multipazIaca: x5chain

    init() throws {
        let pemStr = try String(contentsOf: Bundle.module.url(forResource: "org_multipaz_readerRootCert", withExtension: "pem.txt")!)
        // Split PEM string into individual certificate blocks
        let pemBlocks = pemStr.components(separatedBy: "-----END CERTIFICATE-----")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        multipazIaca = try pemBlocks.map { block in
            let lines = block.components(separatedBy: .newlines)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.hasPrefix("-----") && !$0.isEmpty }
            let base64String = lines.joined()
            let derData = try #require(Data(base64Encoded: base64String))
            return try #require(SecCertificateCreateWithData(nil, derData as CFData))
        }
        #expect(multipazIaca.count == 2)
        for (i, cert) in multipazIaca.enumerated() {
            let certObj = try X509.Certificate(derEncoded: [UInt8](SecCertificateCopyData(cert) as Data))
            print("Certificate \(i + 1) subject:", certObj.subject.description)
        }
    }

	@Test("Reader certificate validations")
	func readerCertificateValidations() throws {
		let cert = try #require(multipazIaca.first)
		let certData = SecCertificateCopyData(cert) as Data
		let certObj = try X509.Certificate(derEncoded: [UInt8](certData))
		print("Certificate subject:", certObj.subject.description)
		let (isValid, messages, _) = SecurityHelpers.isMdocX5cValid(
			secCerts: [cert], usage: .mdocReaderAuth, rootIaca: [multipazIaca])
		#expect(isValid)
		print("Validation messages", messages)
	}

	@Test("CRL parsing")
	func crlParsing() throws {
		let pemStr = try String(contentsOf: Bundle.module.url(forResource: "test", withExtension: "crl")!)
		let crl = try CRL(pemEncoded: pemStr)
		print(crl.revokedSerials.map(\.description))
	}

	// MARK: - isMdocX5cValid with PEM-encoded certificates

	/// Helper to convert a base64 PEM-encoded certificate string to DER Data.
	/// Strips the PEM header/footer and decodes the base64 content.
	private static func derData(fromPEM pem: String) -> Data? {
		let lines = pem.components(separatedBy: .newlines)
			.map { $0.trimmingCharacters(in: .whitespaces) }
			.filter { !$0.hasPrefix("-----") && !$0.isEmpty }
		let base64String = lines.joined()
		return Data(base64Encoded: base64String)
	}

	/// Helper to create a SecCertificate from a PEM string
	private static func secCertificate(fromPEM pem: String) -> SecCertificate? {
		guard let data = derData(fromPEM: pem) else { return nil }
		return SecCertificateCreateWithData(nil, data as CFData)
	}

	@Test("isMdocX5cValid fails with no root IACA certificates")
	func isMdocX5cValidNoRoots() throws {
		let leafCert = try #require(multipazIaca.first)
		let (isValid, messages, rootCert) = SecurityHelpers.isMdocX5cValid(
			secCerts: [leafCert], usage: .mdocReaderAuth, rootIaca: [])
		#expect(!isValid)
		#expect(rootCert == nil)
		#expect(messages.contains(where: { $0.contains("not matched with root certificates") }))
		print("No roots messages:", messages)
	}

	@Test("isMdocX5cValid succeeds with self-signed root IACA certificate")
	func isMdocX5cValidSelfSignedRoot() throws {
		let leafCert = try #require(multipazIaca.first)
		// Use the same cert as a "root" — it is self-signed
		let (isValid, messages, _) = SecurityHelpers.isMdocX5cValid(secCerts: [leafCert], usage: .mdocReaderAuth, rootIaca: [multipazIaca])
		// The cert is self signed
		#expect(isValid)
		print("Messages:", messages)
	}

	@Test("isMdocX5cValid with PEM leaf and root IACA chain", arguments: [
		// Each tuple: (leafPEMs: [String], rootIacaPEMs: [[String]], usage, expectedValid)
		// Test case: empty leaf array
		X5cValidationTestCase(
			name: "Empty leaf certs",
			leafPEMs: [],
			rootIacaPEMs: [],
			usage: .mdocReaderAuth,
			expectedValid: false
		),
	])
	func isMdocX5cValidParameterized(testCase: X5cValidationTestCase) throws {
		let leafCerts = testCase.leafPEMs.compactMap { Self.secCertificate(fromPEM: $0) }
		let rootIaca: [x5chain] = testCase.rootIacaPEMs.map { chain in
			chain.compactMap { Self.secCertificate(fromPEM: $0) }
		}
		let (isValid, messages, _) = SecurityHelpers.isMdocX5cValid(
			secCerts: leafCerts,
			usage: testCase.usage,
			rootIaca: rootIaca
		)
		#expect(isValid == testCase.expectedValid, "Test '\(testCase.name)' expected isValid=\(testCase.expectedValid), got \(isValid). Messages: \(messages)")
		print("Test '\(testCase.name)' messages:", messages)
	}

	/// Convert DER data to a PEM string (for reusing the bundled DER cert in PEM form)
	private func pemFromDERData(_ data: Data) -> String {
		let base64 = data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
		return "-----BEGIN CERTIFICATE-----\n\(base64)\n-----END CERTIFICATE-----"
	}
}

/// Test case for parameterized isMdocX5cValid tests
struct X5cValidationTestCase: Sendable, CustomTestStringConvertible {
	let name: String
	let leafPEMs: [String]
	let rootIacaPEMs: [[String]]
	let usage: CertificateUsage
	let expectedValid: Bool

	var testDescription: String { name }
}
