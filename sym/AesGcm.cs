using System;
using System.Text;
using System.Diagnostics;
using SysCrypto = System.Security.Cryptography;


namespace Cryptool
{

  /// <summary>
  ///   Aes GCM.
  /// </summary>
  public static class AesGcm
  {

    /// <summary>
    ///   Decrypts incoming encrypted payload using AES-GCM.
    ///   No additional data expected.
    /// </summary>
    ///
    /// <param name="key"> Key bytes, must be 32 bytes long. </param>
    ///
    /// <param name="infoCipher"> IV|CipherText|Tag </param>
    ///
    /// <returns> Plain text buffer if success, null otherwise. </returns>
    ///
    /// <exception cref="ArgumentException">
    ///   The key is not 32 bytes long.
    /// </exception>
    ///
    public static byte[]
    Decrypt(byte[] key, byte[] infoCipher)
    {
      if (key == null || key.Length != 32)
      {
        throw new ArgumentException("AesGcm key must be 32 bytes long.");
      }

      // Authentication tag.
      byte[] tag = new byte[16];

      // IV.
      byte[] nonce = new byte[12];

      int cipher_text_len;
      byte[] cipher_text;
      try
      {
        // Length of the cipher_text of interest inside the AES-GCM payload.
        cipher_text_len = infoCipher.Length - tag.Length - nonce.Length;
        cipher_text = new byte[cipher_text_len];

        // Extract each entity of AES-GCM payload.
        Buffer.BlockCopy(infoCipher, infoCipher.Length - tag.Length, tag, 0, tag.Length);
        Buffer.BlockCopy(infoCipher, 0, nonce, 0, nonce.Length);
        Buffer.BlockCopy(infoCipher, nonce.Length, cipher_text, 0, cipher_text_len);
      }
      catch (Exception e)
      {
        Debug.WriteLine(e.Message);
        return null;
      }

      //Debug.WriteLine(
      //    $"tag({Convert.ToBase64String(tag)}), "
      //    + $"nonce({Convert.ToBase64String(nonce)}), "
      //    + $"cipher({Convert.ToBase64String(cipher_text)})"
      //);

      byte[] plain_text = new byte[cipher_text_len];
      using (var c = new SysCrypto.AesGcm(key))
      {
        try
        {
          c.Decrypt(nonce, cipher_text, tag, plain_text, null);
          return plain_text;
        }
        catch (Exception e)
        {
          Debug.WriteLine(e.Message);
          return null;
        }
      }
    }



    /// <summary>
    ///   Encrypts data using AesGcm.
    ///
    ///   If no IV provided, IV is generated.
    /// </summary>
    ///
    /// <param name="key"> Bytes of the key, must be 32 bytes long. </param>
    ///
    /// <param name="plainText"> Plaintext to be encrypted, at least 1 byte. </param>
    ///
    /// <param name="nonce">
    ///   Optional nonce. If null, it will be auto generated.
    ///   If provided, must be 12 bytes long.
    /// </param>
    ///
    /// <returns>
    ///   AesGcm encrypted payload nounce|ciphertext|tag if success,
    ///   `null` otherwise.
    /// </returns>
    ///
    /// <exception cref="ArgumentException">
    ///   The key is not 32 bytes long
    ///   or
    ///   The plain text is null
    ///   or
    ///   The given nonce is not 12 bytes long.
    /// </exception>
    ///
    public static byte[]
    Encrypt(byte[] key, byte[] plainText, byte[] nonce = null)
    {
      if (plainText == null)
      {
        throw new ArgumentException("AesGcm plaintext must not be null.");
      }

      if (key == null || key.Length != 32)
      {
        throw new ArgumentException("AesGcm key must be 32 bytes long.");
      }

      // Authentication tag.
      byte[] tag = new byte[16];

      // IV.
      byte[] _nonce = new byte[12];

      if (nonce == null)
      {
        Rng.GetBytes(_nonce);
      }
      else
      {
        if (nonce.Length != 12)
        {
          throw new ArgumentException("AesGcm must be 12 bytes long.");
        }
        _nonce = nonce;
      }

      byte[] cipherText = new byte[plainText.Length];

      using (var c = new SysCrypto.AesGcm(key))
      {
        try
        {
          c.Encrypt(_nonce, plainText, cipherText, tag, null);
        }
        catch (Exception e)
        {
          Debug.WriteLine(e.Message);
          return null;
        }
      }

      byte[] infoCipher = new byte[_nonce.Length + cipherText.Length + tag.Length];

      Buffer.BlockCopy(
        _nonce, 0,
        infoCipher, 0,
        _nonce.Length
      );

      Buffer.BlockCopy(
        cipherText, 0,
        infoCipher, _nonce.Length,
        cipherText.Length
      );

      Buffer.BlockCopy(
        tag, 0,
        infoCipher, _nonce.Length + cipherText.Length,
        tag.Length
      );

      return infoCipher;
    }


  }
}
