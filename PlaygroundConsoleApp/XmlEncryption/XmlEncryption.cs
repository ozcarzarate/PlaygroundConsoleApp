using System;
using System.Deployment.Internal.CodeSigning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace PlaygroundConsoleApp.XmlEncryption
{
    public class XmlEncryption : IXmlEncryption
    {
        public string Encrypt(string xmlDocument, string elementToEncryptXml, RSA rsaKey, string keyName)
        {
            var xml = new XmlDocument { PreserveWhitespace = true };
            xml.LoadXml(xmlDocument);
            var elementToEncrypt = (XmlElement)xml.GetElementsByTagName(elementToEncryptXml)[0];
            SymmetricAlgorithm sessionKey = null;
            try
            {
                sessionKey = new RijndaelManaged { KeySize = 256 };
                // sessionKey = new TripleDESCryptoServiceProvider();
                // Create a new instance of the EncryptedXml class and use it to encrypt the XmlElement with the a new random symmetric key.
                var encryptedXml = new EncryptedXml();
                var encryptedElement = encryptedXml.EncryptData(elementToEncrypt, sessionKey, false);

                // Construct an EncryptedData object and populate it with the desired encryption information.
                var encryptedData = new EncryptedData
                {
                    Type = EncryptedXml.XmlEncElementUrl,
                    //EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncTripleDESUrl),
                    EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url)
                };

                // Create an EncryptionMethod element so that the receiver knows which algorithm to use for decryption.
                // Encrypt the session key and add it to an EncryptedKey element.
                var encryptedKey = new EncryptedKey();
                var keyEncrypted = EncryptedXml.EncryptKey(sessionKey.Key, rsaKey, false);
                encryptedKey.CipherData = new CipherData(keyEncrypted);
                encryptedKey.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);
                encryptedKey.Recipient = $"name:{keyName}";
                // Add the encrypted key to the EncryptedData object.
                encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));

                // Set the KeyInfo element to specify the name of the RSA key. 
                var keyInfoName = new KeyInfoName { Value = keyName };
                encryptedKey.KeyInfo.AddClause(keyInfoName);

                // Add the encrypted element data to the EncryptedData object.
                encryptedData.CipherData.CipherValue = encryptedElement;

                // Replace the element from the original XmlDocument object with the EncryptedData element.
                EncryptedXml.ReplaceElement(elementToEncrypt, encryptedData, false);

                //var prefixXmlns = "xenc";
                //var xmlns = "http://www.w3.org/2001/04/xmlenc#";
                //var xmlWithPrefix = new XmlDocument{PreserveWhitespace = true};
                //var xElement = XElement.Parse(xml.OuterXml);
                //var xmlElement = xmlWithPrefix.CreateElement(prefixXmlns, xElement.Name.LocalName, xmlns);
                //foreach (var element in xElement.Elements())
                //{
                //    XmlElement node;
                //    if (element.Name.ToString().Contains($"{{{xmlns}}}"))
                //    {
                //        node = xmlWithPrefix.CreateElement(prefixXmlns, element.Name.ToString().Replace($"{{{xmlns}}}", ""), xmlns);
                //        node.InnerText = element.Value;
                //        xmlElement.AppendChild(node);
                //    }

                //}
                //xmlWithPrefix.AppendChild(xmlElement);
                //return xmlWithPrefix.OuterXml;

                return xml.OuterXml;
            }
            catch (Exception e)
            {
                throw e;
            }
            finally
            {
                sessionKey?.Clear();
            }
        }

        public string Decrypt(string encryptedContent, RSA rsaKey, string keyName)
        {
            var xmlEncrypteDocument = new XmlDocument();
            xmlEncrypteDocument.LoadXml(encryptedContent);

            var encryptedXml = new EncryptedXml(xmlEncrypteDocument);
            encryptedXml.AddKeyNameMapping(keyName, rsaKey);
            encryptedXml.DecryptDocument();

            return xmlEncrypteDocument.OuterXml;
        }

        public string Sign(string xmlDocument, RSA rsaKey)
        {
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            var xml = new XmlDocument { PreserveWhitespace = true };
            xml.LoadXml(xmlDocument);
            if (xml.DocumentElement == null)
            {
                throw new CryptographicException($"The xml you are trying to Sign is invalid. \n {xmlDocument}");
            }

            var signedXml = new SignedXml(xml) {SigningKey = rsaKey};
            signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

            var dataObject = new DataObject(Guid.NewGuid().ToString(), "", "", xml.DocumentElement);
            signedXml.AddObject(dataObject);

            var x509Data = new KeyInfoX509Data();
            var x509Certificate2 = new X509Certificate2("NPPAutomationClient.pem");
            if (x509Certificate2.SerialNumber == null)
            {
                throw new CryptographicException("The X509Certificate you are trying to use is invalid. The Serial number is null.");
            }

            var keyInfo = new KeyInfo();
            var keyInfoX509Data = new KeyInfoX509Data();
            keyInfoX509Data.AddIssuerSerial(x509Certificate2.Issuer, x509Certificate2.SerialNumber);
            keyInfoX509Data.AddCertificate(x509Certificate2);
            keyInfo.AddClause(keyInfoX509Data);
            keyInfo.LoadXml(x509Data.GetXml());
            signedXml.KeyInfo = keyInfo;

            var reference = new Reference
            {
                Uri = $"#{dataObject.Id}",
                DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256"
            };
            var env = new XmlDsigC14NTransform();
            reference.AddTransform(env);
            signedXml.AddReference(reference);
            signedXml.ComputeSignature();
            var xmlDigitalSignature = signedXml.GetXml();
            //xml.DocumentElement?.AppendChild(xml.ImportNode(xmlDigitalSignature, true));

            return xml.ImportNode(xmlDigitalSignature, true).OuterXml;
        }

        public bool VerifyXml(string xmlDocument, RSA rsaKey)
        {
            var xml = new XmlDocument { PreserveWhitespace = true };
            xml.LoadXml(xmlDocument);
            var nodeList = xml.GetElementsByTagName("Signature");
            if (nodeList.Count != 1)
            {
                throw new CryptographicException($"This end point can only verify messages with 1 Signature element and the message sent has {nodeList.Count}");
            }
            var signedXml = new SignedXml(xml) { SigningKey = rsaKey };
            signedXml.LoadXml((XmlElement) nodeList[0]);
            return signedXml.CheckSignature(rsaKey);
        }
    }
}