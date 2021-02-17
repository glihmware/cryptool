using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;


namespace Cryptool
{
  /// <summary>
  ///   Abstraction on the top of Hmacsha512 to add functionalities.
  /// </summary>
  ///
  public static class Hmac512
  {
    /// <summary>
    ///   Signature size (512 bits) in bytes.
    /// </summary>
    ///
    public const int SignatureByteLength = 64;

    /// <summary>
    ///   Verifies the hmac signature included in a data buffer.
    ///   The signature must be the first 64 bytes.
    /// </summary>
    ///
    /// <param name="key"> Key used to sign. </param>
    ///
    /// <param name="buf"> Buffer to be signed. </param>
    ///
    /// <returns>
    ///   True if the signature is correct, false otherwise.
    /// </returns>
    ///
    /// <exception cref="ArgumentException">
    ///   The buffer is too short.
    /// </exception>
    ///
    public static bool
    Verify(byte[] key, byte[] buf)
    {
      if (key == null)
      {
        throw new ArgumentException("Hmac key must not be null.");
      }

      if (buf == null | buf.Length < Hmac512.SignatureByteLength + 1)
      {
        throw new ArgumentException("Hmac input buffer's length is too short or null.");
      }

      using (HMACSHA512 hmac = new HMACSHA512(key))
      {
        // Skip the prepended hmac signature.
        byte[] computedSignature = hmac.ComputeHash(
          buf, Hmac512.SignatureByteLength,
          buf.Length - Hmac512.SignatureByteLength
         );

        bool ret;
        if (!BufArray.Compare(
              buf, 0,
              computedSignature, 0,
              Hmac512.SignatureByteLength)
        )
        {
          ret = false;
        }
        else
        {
          ret = true;
        }

        BufArray.Wipe0(hmac.Key);

        return ret;
      }
    }

    /// <summary>
    ///   Verifies the hmac signature included in buf.
    ///   The signature must be the first 64 bytes.
    ///
    ///   The signature is trimmed if the hmac is valid
    ///   and data array is returned.
    /// </summary>
    ///
    /// <param name="key"> Key to verify signature. </param>
    ///
    /// <param name="buf"> Data on which signature was computed. </param>
    ///
    /// <returns>
    ///   Byte array containing the authenticated data if
    ///   the signature is valid, `null` otherwise.
    /// </returns>
    ///
    /// <exception cref="ArgumentException">
    ///   Key is null
    ///   or
    ///   Input buffer is too small or null.
    /// </exception>
    ///
    public static byte[]
    VerifyTrim(byte[] key, byte[] buf)
    {
      if (!Hmac512.Verify(key, buf))
      {
        return null;
      }

      return BufArray.SubArray(
        buf,
        Hmac512.SignatureByteLength,
        buf.Length - Hmac512.SignatureByteLength
      );
    }

    /// <summary>
    ///   Trims the prepended Hmac signature.
    /// </summary>
    ///
    /// <param name="buf"></param>
    ///
    /// <returns></returns>
    ///
    public static byte[]
    TrimSignature(byte[] buf)
    {
      return BufArray.SubArray(
        buf,
        Hmac512.SignatureByteLength,
        buf.Length - Hmac512.SignatureByteLength
      );
    }

    /// <summary>
    ///   Signs the given buffer and prepend the signature.
    /// </summary>
    ///
    /// <param name="key"> Key used to sign. </param>
    ///
    /// <param name="buf"> Data buffer to be signed. </param>
    ///
    /// <returns> Signature and data buffer concatenated. </returns>
    ///
    /// <exception cref="ArgumentException">
    ///   The buffer is too short.
    /// </exception>
    ///
    public static byte[]
    SignPrepend(byte[] key, byte[] buf)
    {
      if (buf.Length < 1)
      {
        throw new Exception("Input buffer's length is too small.");
      }

      byte[] signature = ComputeSignature(key, buf);

      byte[] signed_data = BufArray.Combine(signature, buf);
      return signed_data;

      //using (HMACSHA512 hmac = new HMACSHA512(key))
      //{
      //  byte[] signature = hmac.ComputeHash(buf);

      //  BufArray.Wipe0(hmac.Key);

      //  byte[] signed_data = BufArray.Combine(signature, buf);

      //  return signed_data;
      //}
    }



    /// <summary>
    ///   Computes the HMAC signature.
    /// </summary>
    /// <param name="key"></param>
    /// <param name="buf"></param>
    /// <returns></returns>
    ///
    public static byte[]
    ComputeSignature(byte[] key, byte[] buf)
    {
      using (HMACSHA512 hmac = new HMACSHA512(key))
      {
        byte[] signature = hmac.ComputeHash(buf);

        BufArray.Wipe0(hmac.Key);
        // wipe key?
        return signature;
      }
    }

  }
}
