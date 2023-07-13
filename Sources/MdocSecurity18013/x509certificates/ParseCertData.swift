  import Foundation
  
  public func parseKeyx963(privateKeyData : Data) -> Data? {
    let (result, _) = ASN1.toASN1Element(data: privateKeyData)
    guard case let ASN1.ASN1Element.seq(elements: seq) = result,
        seq.count > 3,
        case let ASN1.ASN1Element.constructed(tag: _, elem: objectElement) = seq[2],
          case ASN1.ASN1Element.bytes(data: _) = objectElement,
        case let ASN1.ASN1Element.bytes(data: privateKeyData) = seq[1]
    else {
        return nil
    }
    guard case let ASN1.ASN1Element.constructed(tag: _, elem: publicElement) = seq[3],
        case let ASN1.ASN1Element.bytes(data: publicKeyData) = publicElement
    else {
      return nil
    }
    let trimmedPubBytes = publicKeyData.drop(while: { $0 == 0x00})
    let keyData = trimmedPubBytes + privateKeyData
    return Data(keyData)
  }

  public func getPublicKeyx963(publicCertData: Data) -> Data? {
    guard let sc = SecCertificateCreateWithData(nil, Data(publicCertData) as CFData) else { return nil }
    guard let secKey = SecCertificateCopyKey(sc) else { return nil }
    var error: Unmanaged<CFError>?
    guard let repr = SecKeyCopyExternalRepresentation(secKey, &error) else { return nil }
    return repr as Data
  }

  