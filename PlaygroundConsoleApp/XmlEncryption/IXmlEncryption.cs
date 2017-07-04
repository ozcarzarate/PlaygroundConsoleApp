using System.Security.Cryptography;

namespace PlaygroundConsoleApp.XmlEncryption
{
    public interface IXmlEncryption
    {
        string Encrypt(string xmlDocument, string elementToEncryptXml, RSA rsaKey, string keyName);

        string Decrypt(string encryptedContent, RSA rsaKey, string keyName);

        string Sign(string xmlDocument, RSA rsaKey);

        bool VerifyXml(string xmlDocument, RSA rsaKey);
    }
}