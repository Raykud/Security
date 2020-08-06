using System;
using System.Security.Cryptography;
using System.Text;
namespace Security
{
    public class Encryption
    {
        public Encryption()
        {
        }


        public static string SHA256(string UrlToHash)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(UrlToHash);
            SHA256Managed hashstring = new SHA256Managed();
            byte[] hash = hashstring.ComputeHash(bytes);
            string hashString = Convert.ToBase64String(hash);
            hashString = hashString.Replace('+', '-');
            hashString = hashString.Replace('/', '_');
            return hashString;
        }


        public static EncryptionResult Encrypt(string ToEncrypt, bool format = true)
        {
            try
            {
                string key = GenerateRandomCryptographicKey();
                string IV = GenerateRandomCryptographicKey();

                byte[] keyA = Encoding.UTF8.GetBytes(key);
                byte[] ivA = Encoding.UTF8.GetBytes(IV);
                byte[] toEncryptA = Encoding.UTF8.GetBytes(ToEncrypt);



                SHA256Managed hashstring = new SHA256Managed();
                byte[] hash = hashstring.ComputeHash(keyA);
                byte[] hashIV = hashstring.ComputeHash(ivA);

                RijndaelManaged aesAlg = new RijndaelManaged
                {
                    Key = hash,
                    Mode = CipherMode.CBC,
                    Padding = PaddingMode.Zeros,
                    BlockSize = 256,
                    IV = hashIV
                };
                ICryptoTransform encryptorRij = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                byte[] outputRij = encryptorRij.TransformFinalBlock(toEncryptA, 0, toEncryptA.Length);

                string outputEncryptionRij = Convert.ToBase64String(outputRij);
                string keyRSA = RSAEncrypt(key);
                string IVRSA = RSAEncrypt(IV);

                if (format)
                {
                    outputEncryptionRij = outputEncryptionRij.Replace('+', '-');
                    outputEncryptionRij = outputEncryptionRij.Replace('/', '_');
                }

                EncryptionResult result = new EncryptionResult(outputEncryptionRij, IVRSA, keyRSA);
                return result;
            }
            catch (Exception ex)
            {
#if __ANDROID__
                Android.Util.Log.Error("Encryption", ex.ToString());
#else
            Console.WriteLine(ex.ToString());
#endif
                return null;
            }
        }

        private static string GenerateRandomCryptographicKey(int keyLength = 64)
        {
            string _Chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ!#%/()=¡¿~[]{}.:,;123456790";
            RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            byte[] randomBytes = new byte[keyLength];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            char[] chars = new char[keyLength];
            int Count = _Chars.Length;

            for (int i = 0; i < keyLength; i++)
            {
                chars[i] = _Chars[randomBytes[i] % Count];
            }
            return new string(chars);
        }

        private static string RSAEncrypt(string plaintext)
        {
            byte[] byteEncoded = Encoding.UTF8.GetBytes(plaintext);
            string PublicKey = "iGvUUk2cGJMzgSDE8oT9Qj8P4thJ8gu/JQwqQ4EPFTyLBsm5WWeIZ0OpMv4hpEYD9/O9dLXqtkLlDHAk4JTTk7BnwbFELzAZOJHm5c8U2hu3ky7Y6eDndc2V+Dm4Ydnb72vRnO+6uZgOdLVHcyAYWyihKIDwFNdK0ZjjR5qH15k=";
            string xmlKey = "<RSAKeyValue><Modulus>" + PublicKey + "</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
            byte[] encryptedData;
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(xmlKey);
            encryptedData = rsa.Encrypt(byteEncoded, false);
            rsa.Dispose();
            string stringData = Convert.ToBase64String(encryptedData);
            stringData = stringData.Replace('+', '-');
            stringData = stringData.Replace('/', '_');
            return stringData;
        }
    }
}