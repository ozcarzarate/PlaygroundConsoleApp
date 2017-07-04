using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace PlaygroundConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            //ProofOfConceptXmlEncryption();
            //ProofOfConceptXmlSigned();
            ProofOfConceptXmlSignedAndEncryption();
            Console.ReadLine();
        }

        private static void ProofOfConceptXmlSignedAndEncryption()
        {
            var collection = new X509Certificate2Collection();
            collection.Import(File.ReadAllBytes("NPPAutomationClient_enc.p12"), "password", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            var x509Certificate2 = collection.Cast<X509Certificate2>()
                .First(c => c.FriendlyName.Equals("NPPAutomationClient", StringComparison.InvariantCultureIgnoreCase));

            var rsaKey = x509Certificate2.PrivateKey as RSACryptoServiceProvider;

            const string keyName = "External_Cert_GCIS";
            var xmlEncryption = new XmlEncryption.XmlEncryption();
            
            var xmlDoc = new XmlDocument { PreserveWhitespace = true };
            xmlDoc.Load("test.xml");

            var signedContent = xmlEncryption.Sign(xmlDoc.OuterXml, rsaKey);
            var xmlSigned = new XmlDocument { PreserveWhitespace = true };
            xmlSigned.LoadXml(signedContent);
            XmlNode docNode = xmlSigned.CreateXmlDeclaration("1.0", "UTF-8", null);
            xmlSigned.InsertBefore(docNode, xmlSigned.FirstChild);
            xmlSigned.Save("test-signed.xml");
            Console.WriteLine("XML file signed.");

            var encryptedContent = xmlEncryption.Encrypt(xmlSigned.OuterXml, "Signature", rsaKey, keyName);
            var xmlEncrypted = new XmlDocument { PreserveWhitespace = true };
            xmlEncrypted.LoadXml(encryptedContent);
            xmlEncrypted.Save("test-encryptedAndSigned.xml");

            Console.WriteLine("Encrypted XML:");
            Console.WriteLine();
            Console.WriteLine(xmlEncrypted.OuterXml);

            var decryptedContent = xmlEncryption.Decrypt(encryptedContent, rsaKey, keyName);
            var xmlDecrypted = new XmlDocument { PreserveWhitespace = true };
            xmlDecrypted.LoadXml(decryptedContent);
            xmlDecrypted.Save("test-decryptedAndSigned.xml");

            Console.WriteLine();
            Console.WriteLine("Decrypted XML:");
            Console.WriteLine();
            Console.WriteLine(xmlDoc.OuterXml);
            
            var valid = xmlEncryption.VerifyXml(signedContent, rsaKey) ? "valid" : "invalid";
            Console.WriteLine($"The signature is {valid}");
        }

        private static void ProofOfConceptXmlSigned()
        {
            var collection = new X509Certificate2Collection();
            collection.Import(File.ReadAllBytes("NPPAutomationClient_enc.p12"), "password", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            var x509Certificate2 = collection.Cast<X509Certificate2>()
                .First(c => c.FriendlyName.Equals("NPPAutomationClient", StringComparison.InvariantCultureIgnoreCase));

            var rsaKey = x509Certificate2.PrivateKey as RSACryptoServiceProvider;

            var xmlEncryption = new XmlEncryption.XmlEncryption();


            var cspParams = new CspParameters {KeyContainerName = "XML_DSIG_RSA_KEY"};
            //This variable is use to proof that Verification works, if we try to verify with this rasKey2 var it will fail
            var rsaKey2 = new RSACryptoServiceProvider(cspParams);

            var xmlDoc = new XmlDocument {PreserveWhitespace = true};
            xmlDoc.Load("test.xml");

            var signedContent = xmlEncryption.Sign(xmlDoc.OuterXml, rsaKey);
            var xmlSigned = new XmlDocument { PreserveWhitespace = true };
            xmlSigned.LoadXml(signedContent);
            XmlNode docNode = xmlSigned.CreateXmlDeclaration("1.0", "UTF-8", null);
            xmlSigned.InsertBefore(docNode, xmlSigned.FirstChild);
            Console.WriteLine("XML file signed.");
            xmlSigned.Save("test-signed.xml");
            var valid = xmlEncryption.VerifyXml(signedContent, rsaKey) ? "valid" : "invalid";
            Console.WriteLine($"The signature is {valid}");
        }

        private static void ProofOfConceptXmlEncryption()
        {
            var collection = new X509Certificate2Collection();
            collection.Import(File.ReadAllBytes("NPPAutomationClient_enc.p12"), "password", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            var x509Certificate2 = collection.Cast<X509Certificate2>()
                .First(c => c.FriendlyName.Equals("NPPAutomationClient", StringComparison.InvariantCultureIgnoreCase));

            var rsaKey = x509Certificate2.PrivateKey as RSACryptoServiceProvider;




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