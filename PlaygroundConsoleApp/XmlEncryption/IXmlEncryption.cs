using System.Security.Cryptography;

namespace PlaygroundConsoleApp.XmlEncryption
{
    public interface IXmlEncryption
    {
        string Encrypt(string xmlDocument, RSA rsaKey);

        string Decrypt(string encryptedContent, RSA rsaKey);

        string Sign(string xmlDocument, RSA rsaKey);

        string VerifyXml(string xmlDocument, RSA rsaKey);
    }
}