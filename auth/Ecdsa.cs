using System;
using System.Diagnostics;
using System.Security.Cryptography;


namespace Cryptool
{

  /// <summary>
  ///
  /// </summary>
  public static class Ecdsa
  {
    /// <summary>
    ///   Generates a new keypair for ECDSA.
    ///
    ///   In ECDSA, the private key also contains the public key.
    /// </summary>
    /// <param name="keySize"></param>
    /// <param name="password"></param>
    /// <returns></returns>
    public static CryptoKeyPair
    GenerateKey(int keySize = 521, string password = null)
    {
      var e = ECDsa.Create();
      e.KeySize = keySize;

      var kp = new CryptoKeyPair()
        {
          KeySize = keySize
        };

      try
      {
        if (!string.IsNullOrEmpty(password))
        {
          var pbe = new PbeParameters(
                                      PbeEncryptionAlgorithm.Aes256Cbc,
                                      HashAlgorithmName.SHA512, 1000);

          kp.Prv = e.ExportEncryptedPkcs8PrivateKey(password, pbe);
        }
        else
        {
          kp.Prv = e.ExportPkcs8PrivateKey();
        }

        kp.Pub = e.ExportSubjectPublicKeyInfo();
        kp.KeySize = keySize;
      }
      catch (Exception)
      {
        return null;
      }
      finally
      {
        e.Dispose();
      }

      return kp;
    }


    /// <summary>
    ///   Signs input data buffer.
    /// </summary>
    /// <param name="kp"></param>
    /// <param name="data"></param>
    /// <param name="password"></param>
    /// <returns></returns>
    public static byte[]
    Sign(CryptoKeyPair kp, byte[] data, string password = null)
    {
      var e = ECDsa.Create();
      e.KeySize = kp.KeySize;

      int n = 0;

      try
      {
        if (!string.IsNullOrEmpty(password))
        {
          e.ImportEncryptedPkcs8PrivateKey(password, kp.Prv, out n);
        }
        else
        {
          e.ImportPkcs8PrivateKey(kp.Prv, out n);
        }

        if (n == 0)
        {
          return null;
        }

        return e.SignData(data, HashAlgorithmName.SHA512);
      }
      catch (Exception)
      {
        return null;
      }
      finally
      {
        e.Dispose();
      }
    }


    /// <summary>
    ///   Verifies the signature on input data buffer.
    /// </summary>
    /// <param name="kp"></param>
    /// <param name="signature"></param>
    /// <param name="data"></param>
    /// <returns></returns>
    public static bool
    Verify(CryptoKeyPair kp, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> data)
    {
      var e = ECDsa.Create();
      e.KeySize = kp.KeySize;

      try
      {
        int n = 0;
        e.ImportSubjectPublicKeyInfo(kp.Pub, out n);

        if (n == 0)
        {
          return false;
        }

        return e.VerifyData(data, signature, HashAlgorithmName.SHA512);
      }
      catch (Exception)
      {
        return false;
      }
      finally
      {
        e.Dispose();
      }
    }

    /// <summary>
    ///   Verifies if the given key can be imported as a valid public key.
    /// </summary>
    /// <param name="pubKey"></param>
    /// <param name="keySize"></param>
    /// <returns></returns>
    public static bool
    VerifyPubKeyImport(byte[] pubKey, int keySize = 521)
    {
      var e = ECDsa.Create();
      e.KeySize = keySize;

      try
      {
        int n;
        e.ImportSubjectPublicKeyInfo(pubKey, out n);
        if (n == 0)
        {
          return false;
        }

        return true;
      }
      catch (Exception)
      {
        return false;
      }
      finally
      {
        e.Dispose();
      }
    }

  }
}
