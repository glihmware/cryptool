using System;
using System.Security.Cryptography;


namespace Cryptool
{

  /// <summary>
  ///   RSA Keypair.
  /// </summary>
  public class RsaKeyPair
  {
    /// <summary>
    ///
    /// </summary>
    public byte[] Pub;

    /// <summary>
    ///
    /// </summary>
    public byte[] Prv;

  }



  /// <summary>
  ///
  /// </summary>
  public static class Rsa
  {
    /// <summary>
    ///   Encrypts data with Rsa OAEP512.
    /// </summary>
    /// <param name="pubKey"></param>
    /// <param name="keySize"></param>
    /// <param name="plain"></param>
    /// <returns></returns>
    public static byte[]
    EncryptOAEP512(byte[] pubKey, int keySize, byte[] plain)
    {
      RSA rsa = RSA.Create();
      rsa.KeySize = keySize;

      int br;
      rsa.ImportSubjectPublicKeyInfo(pubKey, out br);

      try
      {
        return rsa.Encrypt(plain, RSAEncryptionPadding.OaepSHA512);
      }
      catch (Exception)
      {
        // Need better way here...
        return null;
      }
    }


    /// <summary>
    ///   Decrypts data with Rsa OAEP512.
    /// </summary>
    /// <param name="privKey"></param>
    /// <param name="keySize"></param>
    /// <param name="cipher"></param>
    /// <returns></returns>
    public static byte[]
    DecryptOAEP512(byte[] privKey, int keySize, byte[] cipher)
    {
      RSA rsa = RSA.Create();
      rsa.KeySize = keySize;

      int br;
      rsa.ImportPkcs8PrivateKey(privKey, out br);

      try
      {
        return rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA512);
      }
      catch (Exception)
      {
        // Need better way here...
        return null;
      }
    }


  }
}
