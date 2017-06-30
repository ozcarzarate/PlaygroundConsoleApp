using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;

namespace PlaygroundConsoleApp
{
    class Program
    {
        private const string KeyName = "External_Cert_GCIS";
        static void Main(string[] args)
        {
            var xmlDoc = new XmlDocument();
            try
            {
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load("test.xml");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            // Create a new CspParameters object to specify a key container.
            var cspParams = new CspParameters {KeyContainerName = "XML_ENC_RSA_KEY"};
            // Create a new RSA key and save it in the container.  This key will encrypt a symmetric key, which will then be encryped in the XML document.
            var rsaKey = new RSACryptoServiceProvider(cspParams);
            try
            {
                // Encrypt the "creditcard" element.
                var encryptedContent = Encrypt(xmlDoc.OuterXml, "creditcard", rsaKey, KeyName);
                var xmlEncrypted = new XmlDocument();
                xmlEncrypted.PreserveWhitespace = true;
                xmlEncrypted.LoadXml(encryptedContent);

                XmlNode docNode = xmlEncrypted.CreateXmlDeclaration("1.0", "UTF-8", null);
                xmlEncrypted.InsertBefore(docNode, xmlEncrypted.FirstChild);

                //xmlDoc.DocumentElement.SetAttribute("xmlns:xenc", @"http://www.w3.org/2001/04/xmlenc#");

                xmlEncrypted.Save("test-encrypted.xml");

                Console.WriteLine("Encrypted XML:");
                Console.WriteLine();
                Console.WriteLine(xmlEncrypted.OuterXml);
                //xmlDoc.Load(@"D:\Temp\NPP-1561-Xml-Encryption\Request_RecAddRq_inc_BusMsg_Pacs008_signed_encrypted.xml");
                var decryptedContent = Decrypt(encryptedContent, rsaKey, KeyName);
                var xmlDecrypted = new XmlDocument();
                xmlDecrypted.PreserveWhitespace = true;
                xmlDecrypted.LoadXml(decryptedContent);
                xmlDecrypted.Save("test-decrypted.xml");

                Console.WriteLine();
                Console.WriteLine("Decrypted XML:");
                Console.WriteLine();
                Console.WriteLine(xmlDoc.OuterXml);

            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                rsaKey.Clear();
            }


            Console.ReadLine();
        }

        public static string Encrypt(string xmlDocument, string elementToEncryptXml, RSA algorith, string keyName)
        {
            var xml = new XmlDocument {PreserveWhitespace = true};
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
                var keyEncrypted = EncryptedXml.EncryptKey(sessionKey.Key, algorith, false);
                encryptedKey.CipherData = new CipherData(keyEncrypted);
                encryptedKey.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);
                encryptedKey.Recipient = $"name:{keyName}";
                // Add the encrypted key to the EncryptedData object.
                encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));

                // Set the KeyInfo element to specify the name of the RSA key. 
                var keyInfoName = new KeyInfoName {Value = keyName};
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

        public static string Decrypt(string encryptedContent, RSA algorith, string keyName)
        {
            var xmlEncrypteDocument = new XmlDocument();
            xmlEncrypteDocument.LoadXml(encryptedContent);

            // Create a new EncryptedXml object.
            var encryptedXml = new EncryptedXml(xmlEncrypteDocument);

            // Add a key-name mapping. This method can only decrypt documents that present the specified key name.
            encryptedXml.AddKeyNameMapping(keyName, algorith);

            // Decrypt the element.
            encryptedXml.DecryptDocument();

            return xmlEncrypteDocument.OuterXml;
        }

    }
}