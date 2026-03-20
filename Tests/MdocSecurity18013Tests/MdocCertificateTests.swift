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
    var eudiIaca: x5chain

    init() throws {
        let derData = try Data(contentsOf: Bundle.module.url(forResource: "pidissuerca02_ut", withExtension: "der")!)
		eudiIaca = [try #require(SecCertificateCreateWithData(nil, derData as CFData))]
    }

	@Test("CRL parsing")
	func crlParsing() throws {
		guard let url = Bundle.module.url(forResource: "test", withExtension: "crl") else {
			print("CRL file not found")
			return
		}
		let pemStr = try String(contentsOf: url, encoding: .utf8)
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
		let leafCert = try #require(eudiIaca.first)
		let (isValid, messages, rootCert) = SecurityHelpers.isMdocX5cValid(
			secCerts: [leafCert], usage: .mdocReaderAuth, rootIaca: [])
		#expect(!isValid)
		#expect(rootCert == nil)
		#expect(messages.contains(where: { $0.contains("not matched with root certificates") }))
		print("No roots messages:", messages)
	}

	@Test("isMdocX5cValid succeeds with self-signed root IACA certificate")
	func isMdocX5cValidSelfSignedRoot() throws {
		let leafCert = try #require(eudiIaca.first)
		// Use the same cert as a "root" — it is self-signed
		let (isValid, messages, _) = SecurityHelpers.isMdocX5cValid(secCerts: [leafCert], usage: .mdocReaderAuth, rootIaca: [eudiIaca])
		// The cert is self signed
		#expect(isValid)
		print("Messages:", messages)
	}

	@Test("isMdocX5cValid with eudi reader and eudi root IACA chain", arguments: [
		// Each tuple: (leafPEMs: [String], rootIacaPEMs: [[String]], usage, expectedValid)
		// Test case: empty leaf array
		X5cValidationTestCase(
			name: "EUDI reader certs",
			leafPEMs: ["MIIDEDCCAragAwIBAgIUE1oN09EvmTiIbgp1+U580bHJB+MwCgYIKoZIzj0EAwIwXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAyMS0wKwYDVQQKDCRFVURJIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4XDTI1MDQxMDA3NTMxNFoXDTI3MDQxMDA3NTMxM1owVzEdMBsGA1UEAwwURVVESSBSZW1vdGUgVmVyaWZpZXIxCjAIBgNVBAUTATExHTAbBgNVBAoMFEVVREkgUmVtb3RlIFZlcmlmaWVyMQswCQYDVQQGEwJVVDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ82icfMX+TdiUvdHIwqEb6GK12qvPV5voIHjPaQpszCyxztrMKroDWvDdvAnf4LcM5pYOSwRPZeBniCCoglIVmjggFZMIIBVTAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFGLHlEcovQ+iFiCnmsJJlETxAdPHMD0GA1UdEQQ2MDSBEm5vLXJlcGx5QGV1ZGl3LmRldoIeZGV2LnZlcmlmaWVyLWJhY2tlbmQuZXVkaXcuZGV2MBIGA1UdJQQLMAkGByiBjF0FAQYwQwYDVR0fBDwwOjA4oDagNIYyaHR0cHM6Ly9wcmVwcm9kLnBraS5ldWRpdy5kZXYvY3JsL3BpZF9DQV9VVF8wMi5jcmwwHQYDVR0OBBYEFCmeAKpB8pI5fHjL4un1Zs4q3VqEMA4GA1UdDwEB/wQEAwIHgDBdBgNVHRIEVjBUhlJodHRwczovL2dpdGh1Yi5jb20vZXUtZGlnaXRhbC1pZGVudGl0eS13YWxsZXQvYXJjaGl0ZWN0dXJlLWFuZC1yZWZlcmVuY2UtZnJhbWV3b3JrMAoGCCqGSM49BAMCA0gAMEUCIQCgAJYQQgz8w84Autp1slBNPDAF1gS82xyzXCUqQlDE/QIgTzccKF5X980M26fsvyGzyzmp26qtGOwst2wd9dikqmk="],
			usage: .mdocReaderAuth, expectedValid: true
		),
	])
	func isMdocX5cValidParameterized(testCase: X5cValidationTestCase) async throws {
		let leafCerts = testCase.leafPEMs.compactMap { Self.secCertificate(fromPEM: $0) }
		let (isValid, messages, _) = SecurityHelpers.isMdocX5cValid(
			secCerts: leafCerts, usage: testCase.usage, rootIaca: [eudiIaca])
		#expect(isValid == testCase.expectedValid, "Test '\(testCase.name)' expected isValid=\(testCase.expectedValid), got \(isValid). Messages: \(messages)")
		print("Test '\(testCase.name)' messages:", messages)
		let (isValid2, messages2, _) = await SecurityHelpers.isChainFound(secCerts: leafCerts, rootIaca: [eudiIaca])
		#expect(isValid2 == testCase.expectedValid, "Test '\(testCase.name)' expected isValid2=\(testCase.expectedValid), got \(isValid2). Messages: \(messages2)")
	}
}

/// Test case for parameterized isMdocX5cValid tests
struct X5cValidationTestCase: Sendable, CustomTestStringConvertible {
	let name: String
	let leafPEMs: [String]
	let usage: CertificateUsage
	let expectedValid: Bool
	var testDescription: String { name }
}
