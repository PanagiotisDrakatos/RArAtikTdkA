namespace RArAtiTdkA;

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class AesDecrypt
{
    private static string IV = "Y0Xu7RihlxKo47mz";

    public static string Decrypt(string key, string encCipher)
    {
        var textEncoder = new UTF8Encoding();
        var aes = new AesManaged();
        aes.Key = SHA256.Create().ComputeHash(textEncoder.GetBytes(key));
        aes.IV = textEncoder.GetBytes(IV);
        aes.Padding = PaddingMode.PKCS7;
        ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

        using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(encCipher)))
        {
            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            {
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    return srDecrypt.ReadToEnd();
                }
            }
        }
    }
}