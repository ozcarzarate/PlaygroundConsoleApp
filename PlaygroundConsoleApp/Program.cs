using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace PlaygroundConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            // Create an XmlDocument object.
            var xmlDoc = new XmlDocument();

            // Load an XML file into the XmlDocument object.
            try
            {
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load("test.xml");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            // Create a new CspParameters object to specify
            // a key container.
            var cspParams = new CspParameters {KeyContainerName = "XML_ENC_RSA_KEY"};

            // Create a new RSA key and save it in the container.  This key will encrypt
            // a symmetric key, which will then be encryped in the XML document.
            var rsaKey = new RSACryptoServiceProvider(cspParams);

            try
            {
                // Encrypt the "creditcard" element.
                Encrypt(xmlDoc, "creditcard", "EncryptedElement1", rsaKey, "rsaKey");


                // Save the XML document.
                xmlDoc.Save("test-encrypted.xml");

                // Display the encrypted XML to the console.
                Console.WriteLine("Encrypted XML:");
                Console.WriteLine();
                Console.WriteLine(xmlDoc.OuterXml);
                Decrypt(xmlDoc, rsaKey, "rsaKey");
                xmlDoc.Save("test.xml");
                // Display the encrypted XML to the console.
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
                // Clear the RSA key.
                rsaKey.Clear();
            }


            Console.ReadLine();
        }

        public static void Encrypt(XmlDocument doc, string elementToEncryptXml, string encryptionElementId, RSA algorith, string keyName)
        {
            // Check the arguments.
            if (doc == null)
            {
                throw new ArgumentNullException(nameof(doc));
            }
            if (elementToEncryptXml == null)
            {
                throw new ArgumentNullException(nameof(elementToEncryptXml));
            }
            if (encryptionElementId == null)
            {
                throw new ArgumentNullException(nameof(encryptionElementId));
            }
            if (algorith == null)
            {
                throw new ArgumentNullException(nameof(algorith));
            }
            if (keyName == null)
            {
                throw new ArgumentNullException(nameof(keyName));
            }

            ////////////////////////////////////////////////
            // Find the specified element in the XmlDocument
            // object and create a new XmlElemnt object.
            ////////////////////////////////////////////////
            var elementToEncrypt = doc.GetElementsByTagName(elementToEncryptXml)[0] as XmlElement;

            // Throw an XmlException if the element was not found.
            if (elementToEncrypt == null)
            {
                throw new XmlException("The specified element was not found");

            }
            RijndaelManaged sessionKey = null;

            try
            {
                //////////////////////////////////////////////////
                // Create a new instance of the EncryptedXml class
                // and use it to encrypt the XmlElement with the
                // a new random symmetric key.
                //////////////////////////////////////////////////

                // Create a 256 bit Rijndael key.
                sessionKey = new RijndaelManaged {KeySize = 256};

                var eXml = new EncryptedXml();

                var encryptedElement = eXml.EncryptData(elementToEncrypt, sessionKey, false);
                ////////////////////////////////////////////////
                // Construct an EncryptedData object and populate
                // it with the desired encryption information.
                ////////////////////////////////////////////////

                var edElement = new EncryptedData
                {
                    Type = EncryptedXml.XmlEncElementUrl,
                    Id = encryptionElementId,
                    EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncTripleDESUrl)
                };
                // Create an EncryptionMethod element so that the
                // receiver knows which algorithm to use for decryption.

                // Encrypt the session key and add it to an EncryptedKey element.
                var ek = new EncryptedKey();

                var encryptedKey = EncryptedXml.EncryptKey(sessionKey.Key, algorith, false);

                ek.CipherData = new CipherData(encryptedKey);

                ek.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);

                // Create a new DataReference element
                // for the KeyInfo element.  This optional
                // element specifies which EncryptedData
                // uses this key.  An XML document can have
                // multiple EncryptedData elements that use
                // different keys.
                var dRef = new DataReference {Uri = "#" + encryptionElementId};

                // Specify the EncryptedData URI.

                // Add the DataReference to the EncryptedKey.
                ek.AddReference(dRef);
                // Add the encrypted key to the
                // EncryptedData object.

                edElement.KeyInfo.AddClause(new KeyInfoEncryptedKey(ek));
                // Set the KeyInfo element to specify the
                // name of the RSA key.


                // Create a new KeyInfoName element.
                var kin = new KeyInfoName {Value = keyName};

                // Specify a name for the key.

                // Add the KeyInfoName element to the
                // EncryptedKey object.
                ek.KeyInfo.AddClause(kin);
                // Add the encrypted element data to the
                // EncryptedData object.
                edElement.CipherData.CipherValue = encryptedElement;
                ////////////////////////////////////////////////////
                // Replace the element from the original XmlDocument
                // object with the EncryptedData element.
                ////////////////////////////////////////////////////
                EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);
            }
            catch (Exception e)
            {
                // re-throw the exception.
                throw e;
            }
            finally
            {
                sessionKey?.Clear();
            }

        }

        public static void Decrypt(XmlDocument document, RSA algorith, string keyName)
        {
            // Check the arguments.  
            if (document == null)
            {
                throw new ArgumentNullException(nameof(document));
            }
            if (algorith == null)
            {
                throw new ArgumentNullException(nameof(algorith));
            }
            if (keyName == null)
            {
                throw new ArgumentNullException(nameof(keyName));
            }

            // Create a new EncryptedXml object.
            var exml = new EncryptedXml(document);

            // Add a key-name mapping.
            // This method can only decrypt documents
            // that present the specified key name.
            exml.AddKeyNameMapping(keyName, algorith);

            // Decrypt the element.
            exml.DecryptDocument();

        }

    }
}