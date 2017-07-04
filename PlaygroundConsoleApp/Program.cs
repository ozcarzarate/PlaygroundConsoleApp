using System;
using System.Security.Cryptography;
using System.Xml;

namespace PlaygroundConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            //ProofOfConceptXmlEncryption();
            ProofOfConceptXmlSigned();
            Console.ReadLine();
        }

        private static void ProofOfConceptXmlSigned()
        {
            var cspParams2 = new CspParameters { KeyContainerName = "XML_ENC_RSA_KEY" };
            var rsaKey2 = new RSACryptoServiceProvider(cspParams2);

            var xmlEncryption = new XmlEncryption.XmlEncryption();

            var cspParams = new CspParameters {KeyContainerName = "XML_DSIG_RSA_KEY"};
            var rsaKey = new RSACryptoServiceProvider(cspParams);
            var xmlDoc = new XmlDocument {PreserveWhitespace = true};
            xmlDoc.Load("test.xml");

            var signedContent = xmlEncryption.Sign(xmlDoc.OuterXml, rsaKey);
            var xmlSigned = new XmlDocument { PreserveWhitespace = true };
            xmlSigned.LoadXml(signedContent);
            XmlNode docNode = xmlSigned.CreateXmlDeclaration("1.0", "UTF-8", null);
            xmlSigned.InsertBefore(docNode, xmlSigned.FirstChild);
            Console.WriteLine("XML file signed.");
            xmlSigned.Save("test-signed.xml");
            var valid = xmlEncryption.VerifyXml(signedContent, rsaKey2) ? "valid" : "invalid";
            Console.WriteLine($"The signature is {valid}");
        }

        private static void ProofOfConceptXmlEncryption()
        {
            var xmlEncryption = new XmlEncryption.XmlEncryption();

            const string keyName = "External_Cert_GCIS";
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
            var cspParams = new CspParameters { KeyContainerName = "XML_ENC_RSA_KEY" };
            // Create a new RSA key and save it in the container.  This key will encrypt a symmetric key, which will then be encryped in the XML document.
            var rsaKey = new RSACryptoServiceProvider(cspParams);
            try
            {
                // Encrypt the "creditcard" element.
                var encryptedContent = xmlEncryption.Encrypt(xmlDoc.OuterXml, "creditcard", rsaKey, keyName);
                var xmlEncrypted = new XmlDocument {PreserveWhitespace = true};
                xmlEncrypted.LoadXml(encryptedContent);

                XmlNode docNode = xmlEncrypted.CreateXmlDeclaration("1.0", "UTF-8", null);
                xmlEncrypted.InsertBefore(docNode, xmlEncrypted.FirstChild);

                //xmlDoc.DocumentElement.SetAttribute("xmlns:xenc", @"http://www.w3.org/2001/04/xmlenc#");

                xmlEncrypted.Save("test-encrypted.xml");

                Console.WriteLine("Encrypted XML:");
                Console.WriteLine();
                Console.WriteLine(xmlEncrypted.OuterXml);
                //xmlDoc.Load(@"D:\Temp\NPP-1561-Xml-Encryption\Request_RecAddRq_inc_BusMsg_Pacs008_signed_encrypted.xml");
                var decryptedContent = xmlEncryption.Decrypt(encryptedContent, rsaKey, keyName);
                var xmlDecrypted = new XmlDocument {PreserveWhitespace = true};
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
        }
    }
}