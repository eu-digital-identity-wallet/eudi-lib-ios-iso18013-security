// IssuerAuthentication.swift
import Foundation
import SwiftCBOR
import MdocDataModel18013
import CryptoKit

public struct IssuerAuthentication {
	public static var isoDateFormatter: ISO8601DateFormatter = {let df = ISO8601DateFormatter(); df.formatOptions = [.withFullDate, .withTime, .withTimeZone, .withColonSeparatorInTime, .withDashSeparatorInDate]; return df}()

	public static func getHash(_ d:DigestAlgorithmKind, bytes: [UInt8]) -> Data {
		switch d {
		case .SHA256: let h = SHA256.hash(data:Data(bytes)); return h.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> Data in Data(p[0..<p.count]) }
		case .SHA384: let h = SHA384.hash(data:Data(bytes)); return h.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> Data in Data(p[0..<p.count]) }
		case .SHA512: let h = SHA512.hash(data:Data(bytes)); return h.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> Data in Data(p[0..<p.count]) }
		}
	}
	
	public static func validateDigest(for signedItem: IssuerSignedItem, dak: DigestAlgorithmKind, digest: [UInt8]?) -> Bool {
		guard let digest else {return false}
		let issuerSignedItemBytes = signedItem.encode(options: CBOROptions()).taggedEncoded.encode()
		let itemDigest = Self.getHash(dak, bytes: issuerSignedItemBytes)
		if itemDigest == Data(digest) { return true }
		return false
	}
	
	public static func validateDigests(for document: Document, mso: MobileSecurityObject) -> (Bool, [String: Bool]) {
		guard let issuerNamespaces = document.issuerSigned.nameSpaces?.issuerNameSpaces, let dak = DigestAlgorithmKind(rawValue: mso.digestAlgorithm) else { return (false, [:]) }
		var failedElements = [String: Bool]()
		var result = (true, failedElements)
		for (ns,items) in issuerNamespaces {
			for item in items {
				let ok = validateDigest(for: item, dak: dak, digest: mso.valueDigests[ns]?[item.digestID])
				if !ok {
					failedElements[item.elementIdentifier] = false
					logger.info("Failed digest validation for \(item.elementIdentifier)")
					result = (false, failedElements)
				}
			}
		}
		return result
	}
	
	// temporary function, mso should come from the server
	public static func makeDefaultMSO(for document: Document, iaca: Data) -> MobileSecurityObject? {
		let dak = MobileSecurityObject.defaultDigestAlgorithmKind
		guard let issuerNamespaces = document.issuerSigned.nameSpaces?.issuerNameSpaces else { return nil }
		var vd = [NameSpace: DigestIDs]()
		for (ns,items) in issuerNamespaces {
			var dids = [DigestID: [UInt8]]()
			for item in items {
				let issuerSignedItemBytes = item.encode(options: CBOROptions()).taggedEncoded.encode()
				let itemDigest = Self.getHash(dak, bytes: issuerSignedItemBytes)
				dids[item.digestID] = [UInt8](itemDigest)
			}
			vd[ns] = DigestIDs(digestIDs: dids)
		}
		let valueDigests = ValueDigests(valueDigests: vd)
		let validityInfo = ValidityInfo(signed: isoDateFormatter.string(from: Date()), validFrom: isoDateFormatter.string(from: Date()), validUntil: isoDateFormatter.string(from: Calendar.current.date(byAdding: .month, value: 2, to: Date())!))
		guard let publicKey963 = getPublicKeyx963(publicCertData: iaca) else { return nil }
		let deviceKey = CoseKey(crv: .p256, x963Representation: publicKey963)
		let mso = MobileSecurityObject(version: MobileSecurityObject.defaultVersion, digestAlgorithm: dak.rawValue, valueDigests: valueDigests, deviceKey: deviceKey, docType: document.docType, validityInfo: validityInfo)
		return mso
	}
	
	public static func makeDefaultIssuerAuth(for document: Document, iaca: Data) throws -> IssuerAuth? {
		guard let publicKey963 = getPublicKeyx963(publicCertData: iaca) else { return nil }
		guard let mso = makeDefaultMSO(for: document, iaca: iaca) else { return nil }
		let msoRawData = mso.toCBOR(options: CBOROptions()).encode()
		let signature = try Cose.computeSignatureValue(Data(msoRawData), deviceKey_x963: publicKey963, alg: .es256)
		let ia = IssuerAuth(mso: mso, msoRawData: msoRawData, verifyAlgorithm: .es256, signature: signature, iaca: [iaca.bytes])
		return ia
	}
}
