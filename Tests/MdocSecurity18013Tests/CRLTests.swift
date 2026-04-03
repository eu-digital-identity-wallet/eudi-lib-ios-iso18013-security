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
import SwiftASN1
import X509

@testable import MdocSecurity18013

@Suite("CRL Tests")
struct CRLTests {

	// Valid CRL with no revoked certificates (nextUpdate: 2036-03-31)
	static let validEmptyCRLPEM = """
	-----BEGIN X509 CRL-----
	MIGpMFECAQEwCgYIKoZIzj0EAwIwEjEQMA4GA1UEAwwHVGVzdCBDQRcNMjYwNDAz
	MTIxMjI5WhcNMzYwMzMxMTIxMjI5WqAOMAwwCgYDVR0UBAMCAQEwCgYIKoZIzj0E
	AwIDSAAwRQIhALnLjSZVZeQ0GrnA9zZyPkQn4strgYXZCIhQmGxmyPNMAiBJDzHV
	FLYTXJLcqvELdLUi++W5nDtJ3+MaSSRgnQPrZw==
	-----END X509 CRL-----
	"""

	// Valid CRL with one revoked certificate (serial 02), nextUpdate: 2036-03-31
	static let validRevokedCRLPEM = """
	-----BEGIN X509 CRL-----
	MIG/MGcCAQEwCgYIKoZIzj0EAwIwEjEQMA4GA1UEAwwHVGVzdCBDQRcNMjYwNDAz
	MTIxMjM4WhcNMzYwMzMxMTIxMjM4WjAUMBICAQIXDTI2MDQwMzEyMTIzN1qgDjAM
	MAoGA1UdFAQDAgECMAoGCCqGSM49BAMCA0gAMEUCIE2Zaqwj3xW+K9/dBPmGvlKT
	bp+KTnC8cirWvJZNqjE/AiEAun0smHy5Xmf9Pp010T0/iFxUv7eK0cSBHcuxOBTe
	aXU=
	-----END X509 CRL-----
	"""

	// Expired CRL (nextUpdate: 2026-04-03T12:12:46Z - already passed)
	static let expiredCRLPEM = """
	-----BEGIN X509 CRL-----
	MIG/MGcCAQEwCgYIKoZIzj0EAwIwEjEQMA4GA1UEAwwHVGVzdCBDQRcNMjYwNDAz
	MTIxMjQ1WhcNMjYwNDAzMTIxMjQ2WjAUMBICAQIXDTI2MDQwMzEyMTIzN1qgDjAM
	MAoGA1UdFAQDAgEDMAoGCCqGSM49BAMCA0gAMEUCIQDGu2YEaVYFqjUK5wcMxbFe
	1PpLDgS+wyMPWkS4QM+3zgIgNJIoLbaRsGliNw9wC7QAX0Ok96z+h+NjiG1LSSMM
	j0o=
	-----END X509 CRL-----
	"""

	@Test("Parse valid CRL with no revoked certificates")
	func parseEmptyCRL() throws {
		let crl = try CRL(pemEncoded: Self.validEmptyCRLPEM)

		#expect(crl.version == 1) // CRL v2
		#expect(crl.issuer.description.contains("Test CA"))
		#expect(crl.revokedSerials.isEmpty)

		// thisUpdate: 2026-04-03, nextUpdate: 2036-03-31
		#expect(crl.thisUpdate.year == 2026)
		#expect(crl.thisUpdate.month == 4)
		#expect(crl.thisUpdate.day == 3)
		#expect(crl.nextUpdate.year == 2036)
		#expect(crl.nextUpdate.month == 3)
		#expect(crl.nextUpdate.day == 31)
	}

	@Test("Parse CRL with revoked certificate")
	func parseRevokedCRL() throws {
		let crl = try CRL(pemEncoded: Self.validRevokedCRLPEM)

		#expect(crl.version == 1)
		#expect(crl.issuer.description.contains("Test CA"))
		#expect(crl.revokedSerials.count == 1)

		// The revoked serial number is 02
		let revokedSerial = try #require(crl.revokedSerials.first)
		#expect(revokedSerial.serial.description.contains("2"))

		// Revocation date should be 2026-04-03
		#expect(revokedSerial.date.year == 2026)
		#expect(revokedSerial.date.month == 4)
		#expect(revokedSerial.date.day == 3)
	}

	@Test("Valid CRL passes validity check")
	func validCRLIsValid() throws {
		let crl = try CRL(pemEncoded: Self.validRevokedCRLPEM)
		// nextUpdate is 2036, so this should be valid now
		#expect(crl.isValid)
	}

	@Test("Expired CRL fails validity check")
	func expiredCRLIsNotValid() throws {
		let crl = try CRL(pemEncoded: Self.expiredCRLPEM)
		// nextUpdate was 2026-04-03T12:12:46Z - already expired
		#expect(!crl.isValid)
	}

	@Test("CRL field names match X.509 spec")
	func fieldNamesMatchSpec() throws {
		let crl = try CRL(pemEncoded: Self.validEmptyCRLPEM)
		// Verify the fields are named according to X.509 CRL spec
		_ = crl.thisUpdate  // was incorrectly named 'validity'
		_ = crl.nextUpdate  // was incorrectly named 'subject'
		_ = crl.version     // was incorrectly named 'serialNumber'
		_ = crl.issuer
		_ = crl.revokedSerials
	}
}
