using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using System.Security.Cryptography;
using System.Text;


namespace WebAPI.Controllers
{
    public static class EncryptionHelper
    {
        private static readonly int KeySize = 256;
        private static readonly int Iterations = 10000;

        public static string Encrypt(string plainText, string password)
        {
            using (var aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Key = GenerateKey(password, KeySize);
                aesAlg.GenerateIV();

                using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }

                    return Convert.ToBase64String(aesAlg.IV.Concat(msEncrypt.ToArray()).ToArray());
                }
            }
        }

        public static string Decrypt(string cipherText, string password)
        {
            // password = UID + SERVER_SECRET
            if (string.IsNullOrEmpty(cipherText))
            {
                return cipherText;
            }
            try
            {
                using (var aesAlg = new AesCryptoServiceProvider())
                {
                    aesAlg.Key = GenerateKey(password, KeySize);

                    var fullCipher = Convert.FromBase64String(cipherText);

                    aesAlg.IV = fullCipher.Take(aesAlg.BlockSize / 8).ToArray();

                    byte[] encryptedData = fullCipher.Skip(aesAlg.BlockSize / 8).ToArray();

                    using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                    using (var msDecrypt = new MemoryStream(encryptedData))
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    using (var srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
            catch (Exception ex)
            {

                return cipherText;
            }
        }

        private static byte[] GenerateKey(string password, int keySize)
        {
            byte[] salt = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, Iterations))
            {
                return deriveBytes.GetBytes(keySize / 8);
            }
        }

        public static string EncryptStringWithPublicKeyDerFile(string publicKeyPath, string plainText)
        {
            byte[] publicKeyStr = File.ReadAllBytes(publicKeyPath);
            return EncryptStringWithPublicKey(publicKeyStr, plainText);
        }
        public static string EncryptStringWithPublicKey(byte[] publicKeyBytes, string plainText)
        {
            using RSA rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

            // Encrypt the plaintext with RSA-OAEP
            byte[] ciphertext = rsa.Encrypt(Encoding.UTF8.GetBytes(plainText), RSAEncryptionPadding.OaepSHA256);
            return Convert.ToBase64String(ciphertext);
        }

        public static string DecryptStringWithPrivateKeyPemFile(string privateKeyPath, string encryptedText)
        {
            string privateKeyStr = File.ReadAllText(privateKeyPath);
            return DecryptStringWithPrivateKey(privateKeyStr, encryptedText);
        }

        public static string DecryptStringWithPrivateKey(string privateKeyPemStr, string encryptedText)
        {
            using RSA rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPemStr);

            byte[] strBytes = Convert.FromBase64String(encryptedText);
            Console.WriteLine(strBytes);
            byte[] originBytes = rsa.Decrypt(strBytes, RSAEncryptionPadding.OaepSHA256);
            Console.WriteLine(originBytes);
            return Encoding.UTF8.GetString(originBytes);
        }

        public static string Aes256(string plaintext, string key, string iv)
        {
            byte[] bKey = Encoding.UTF8.GetBytes(key);
            byte[] bIV = Encoding.UTF8.GetBytes(iv);
            using var aes = new AesCryptoServiceProvider
            {
                KeySize = 256,
                Key = bKey,
                IV = bIV,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };
            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            using (StreamWriter sw = new StreamWriter(cs))
            {
                sw.Write(plaintext);
            }
            byte[] encrypted = ms.ToArray();
            return Convert.ToBase64String(encrypted);
        }

        public static string DecryptAes256(string base64Ciphertext, string key, string iv)
        {
            byte[] ciphertextBytes = Convert.FromBase64String(base64Ciphertext);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = Encoding.UTF8.GetBytes(iv);

            using Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.Key = keyBytes;
            aes.IV = ivBytes;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using MemoryStream msDecrypt = new MemoryStream(ciphertextBytes);
            using CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using StreamReader srDecrypt = new StreamReader(csDecrypt);
            return srDecrypt.ReadToEnd();
        }

        public static string RandomHex(int length)
        {
            byte[] bytes = new byte[length / 2];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(bytes);
            }
            return BitConverter.ToString(bytes).Replace("-", "");
        }

        public static string EncryptJsonPayloadWithPublicKeyDerFile(string publicKeyFilePath, string jsonString)
        {
            byte[] publicKeyBytes = File.ReadAllBytes(publicKeyFilePath);
            return EncryptJsonPayloadWithPublicKey(publicKeyBytes, jsonString);
        }

        public static string EncryptJsonPayloadWithPublicKeyPemFile(string publicPemFilePath, string jsonString)
        {
            string publicPemStr = File.ReadAllText(publicPemFilePath);
            byte[] publicKeyBytes = ConvertPemToDer(publicPemStr);
            return EncryptJsonPayloadWithPublicKey(publicKeyBytes, jsonString);
        }

        public static string EncryptJsonPayloadWithPublicKey(byte[] publicKeyBytes, string jsonString)
        {
            string key = RandomHex(32);
            string iv = RandomHex(16);
            string encryptPayload = Aes256(jsonString, key, iv);
            string keyStr = key + iv;
            string base64EncryptKey = EncryptStringWithPublicKey(publicKeyBytes, keyStr);
            return encryptPayload + "," + base64EncryptKey;
        }

        public static string DecryptJsonPayloadWithPrivateKeyPemFile(string privateKeyFilePath, string encryptedString)
        {
            string privateKeyPemStr = File.ReadAllText(privateKeyFilePath);
            return DecryptJsonPayloadWithPrivateKey(privateKeyPemStr, encryptedString);
        }

        public static string DecryptJsonPayloadWithPrivateKey(string privateKeyPemStr, string encryptedString)
        {
            string[] encryptedArr = encryptedString.Split(',');
            string keyStr = DecryptStringWithPrivateKey(privateKeyPemStr, encryptedArr[1]);
            string originKey = keyStr.Substring(0, 32);
            string originIv = keyStr.Substring(32);
            string originText = DecryptAes256(encryptedArr[0], originKey, originIv);
            return originText;
        }

        public static byte[] ConvertPemToDer(string pemStr)
        {
            using (StringReader stringReader = new StringReader(pemStr))
            {
                PemReader pemReader = new PemReader(stringReader);
                object obj = pemReader.ReadObject();
                RsaKeyParameters param = (RsaKeyParameters)obj;
                SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(param);
                return info.GetEncoded();
            }
        }

        static void test()
        {

            string publicKeyDerPath = "C:\\encryption\\public_key.der";
            string publicPemFilePath = "C:\\encryption\\public_key.pem";
            string privateKeyPath = "C:\\encryption\\private_key.pem";
            string plaintext = "{\"data\": \"abc\"}";
            string encryptedPublic = EncryptJsonPayloadWithPublicKeyDerFile(publicKeyDerPath, plaintext);
            string decryptedStr = DecryptJsonPayloadWithPrivateKeyPemFile(privateKeyPath, encryptedPublic);
            Console.WriteLine("decryptedStr: " + decryptedStr);
            Console.WriteLine("encryptedStr: " + encryptedPublic.Split(",").Length + "  >>>   " + encryptedPublic);

            string encryptedPublic2 = EncryptJsonPayloadWithPublicKeyPemFile(publicPemFilePath, plaintext);
            string decruptedStr2 = DecryptJsonPayloadWithPrivateKeyPemFile(privateKeyPath, encryptedPublic2);
            Console.WriteLine("decryptedStr2: " + decruptedStr2);
        }
    }

}
