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
    ///
    /// </summary>
    /// <param name="keySize"></param>
    /// <param name="password"></param>
    /// <returns></returns>
    public static CryptoKeyPair
    GenerateKeys(int keySize = 4096, string password = null)
    {
      var rsa = RSA.Create();
      rsa.KeySize = keySize;

      var kp = new CryptoKeyPair();

      try
      {

        if (!string.IsNullOrEmpty(password))
        {
          var pbe = new PbeParameters(
                                      PbeEncryptionAlgorithm.Aes256Cbc,
                                      HashAlgorithmName.SHA512, 1000);

          kp.Prv = rsa.ExportEncryptedPkcs8PrivateKey(password, pbe);
        }
        else
        {
          kp.Prv = rsa.ExportPkcs8PrivateKey();
        }

        kp.Pub = rsa.ExportSubjectPublicKeyInfo();
        kp.KeySize = keySize;
      }
      catch (Exception)
      {
        return null;
      }
      finally
      {
        rsa.Dispose();
      }

      return kp;
    }

    /// <summary>
    ///
    /// </summary>
    /// <param name="kp"></param>
    /// <param name="plain"></param>
    /// <returns></returns>
    public static byte[]
    EncryptOAEP512(CryptoKeyPair kp, byte[] plain)
    {
      var rsa = RSA.Create();
      rsa.KeySize = kp.KeySize;

      try
      {
        int n;
        rsa.ImportSubjectPublicKeyInfo(kp.Pub, out n);

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
      catch (Exception)
      {
        return null;
      }
      finally
      {
        rsa.Dispose();
      }
    }


    /// <summary>
    ///
    /// </summary>
    /// <param name="kp"></param>
    /// <param name="cipher"></param>
    /// <param name="password"></param>
    /// <returns></returns>
    public static byte[]
    DecryptOAEP512(CryptoKeyPair kp, byte[] cipher, string password = null)
    {
      var rsa = RSA.Create();
      rsa.KeySize = kp.KeySize;

      try
      {
        int n;
        if (!string.IsNullOrEmpty(password))
        {
          rsa.ImportEncryptedPkcs8PrivateKey(password, kp.Prv, out n);
        }
        else
        {
          rsa.ImportPkcs8PrivateKey(kp.Prv, out n);
        }

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
      catch (Exception)
      {
        return null;
      }
      finally
      {
        rsa.Dispose();
      }
    }


    /// <summary>
    ///   Verifies if the given key can be imported as a valid public key.
    /// </summary>
    /// <param name="pubKey"></param>
    /// <param name="keySize"></param>
    /// <returns></returns>
    public static bool
    VerifyPubKeyImport(byte[] pubKey, int keySize = 4096)
    {
      var rsa = RSA.Create();
      rsa.KeySize = keySize;

      try
      {
        int n;
        rsa.ImportSubjectPublicKeyInfo(pubKey, out n);
        if (n == 0)
        {
          return false;
        }
      }
      catch (Exception)
      {
        return false;
      }
      finally
      {
        rsa.Dispose();
      }

      return true;
    }

  }
}
