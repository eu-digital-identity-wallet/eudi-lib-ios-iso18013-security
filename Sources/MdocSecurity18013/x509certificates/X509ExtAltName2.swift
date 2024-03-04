import Foundation
import ASN1Decoder



public class X509ExtAltName2 {
    private let asn1: [ASN1Object]
    private let block1: ASN1Object

      public init(der: Data) throws {
        asn1 = try ASN1DERDecoder.decode(data: der)
        guard asn1.count > 0,let block1 = asn1.first?.sub(0) else {
          throw X509CRLError.parseError
        }
        self.block1 = block1
    }
    /// Gets a collection of issuer alternative names from the IssuerAltName extension, (OID = 2.5.29.18).
    public var issuerAlternativeNamesAndTypes: [UInt8:String]? {
        return extensionObject(oid: OID.issuerAltName)?.alternativeNamesAndTypes
    }
        /// Gets the extension information of the given OID enum.
    public func extensionObject(oid: OID) -> X509ExtensionAltName2? {
        return extensionObject(oid: oid.rawValue)
    }
        /// Gets the extension information of the given OID code.
    public func extensionObject(oid: String) -> X509ExtensionAltName2? {
        return block1.sub(7)?
            .findOid(oid)?
            .parent
            .map { X509ExtensionAltName2(block: $0) }
    }
}

public class X509ExtensionAltName2 {

    let block: ASN1Object

    required init(block: ASN1Object) {
        self.block = block
    }


    // Used for SubjectAltName and IssuerAltName
    // Every name can be one of these subtype:
    //  - otherName      [0] INSTANCE OF OTHER-NAME,
    //  - rfc822Name     [1] IA5String, -------
    //  - dNSName        [2] IA5String,
    //  - x400Address    [3] ORAddress,
    //  - directoryName  [4] Name,
    //  - ediPartyName   [5] EDIPartyName,
    //  - uniformResourceIdentifier [6] IA5String, -------
    //  - IPAddress      [7] OCTET STRING,
    //  - registeredID   [8] OBJECT IDENTIFIER
    //
    // Result does not support: x400Address and ediPartyName
    //
    var alternativeNamesAndTypes: [UInt8: String] {
        var result: [UInt8: String] = [:]
        guard let sl = block.subLast?.subLast, sl.subCount() > 0 else { return result }
        for i in 0..<sl.subCount() {
            guard let item = sl.sub(i) else { continue}
            guard let pair = generalName(of: item) else { continue }
            result[pair.0] = pair.1
        }
        return result
    }
    
    func generalName(of item: ASN1Object) -> (UInt8,String)? {
        guard let nameType = item.identifier?.tagNumber().rawValue else {
            return nil
        }
        switch nameType {
        case 0:
            if let name = item.subLast?.subLast?.value as? String {
                return (nameType, name)
            }
        case 1, 2, 6:
            if let name = item.value as? String {
                return (nameType, name)
            }
        default:
            return nil
        }
        return nil
    }
}

extension ASN1Object {
	var subLast: ASN1Object? { subCount() == 0 ? nil : sub(subCount()-1) }
	
	static func hasDuplicateExtensions(der: Data) -> Bool {
		guard let asn1 = try? ASN1DERDecoder.decode(data: der) else {return false }
		guard asn1.count > 0, let block1 = asn1.first?.sub(0) else { return false }
		guard let asn1pos7 = block1.sub(7)?.sub(0) else { return false }
		let extensionBlocks = (0..<asn1pos7.subCount()).map { asn1pos7.sub($0) }
		let extensionsOids = extensionBlocks.compactMap { $0?.sub(0)?.value as? String }
		return Set(extensionsOids).count < extensionsOids.count
	}
}
