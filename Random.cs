using System;
using System.Security.Cryptography;


namespace Cryptool
{
  /// <summary>
  ///   Random data for cryptography.
  /// </summary>
  ///
  public static class Rng
  {
    /// <summary>
    ///   Random generator.
    /// </summary>
    ///
    private static RNGCryptoServiceProvider rngCsp =
      new RNGCryptoServiceProvider();


    /// <summary>
    ///   Generates a random U64 value.
    /// </summary>
    ///
    /// <param name="min"> Lower limit, included. </param>
    ///
    /// <param name="max"> Upper limit, included. </param>
    ///
    /// <returns> Random ulong. </returns>
    ///
    public static ulong
    U64(ulong min = UInt64.MinValue, ulong max = UInt64.MaxValue)
    {
      if (min > max)
      {
        throw new ArgumentException("min must be <= to max");
      }

      byte[] bytes = new byte[8];

    generate:
      rngCsp.GetBytes(bytes);

      ulong r = (ulong)(
        bytes[0] << 56
      | bytes[1] << 48
      | bytes[2] << 40
      | bytes[3] << 32
      | bytes[4] << 24
      | bytes[5] << 16
      | bytes[6] << 8
      | bytes[7]
      );

      if (r < min || r > max)
      {
        goto generate;
      }

      return r;
    }


    /// <summary>
    ///   Generates random numbers to fill the given array.
    /// </summary>
    ///
    /// <returns> Random generated bytes. </returns>
    ///
    public static void GetBytes(byte[] buf)
    {
      if (buf.Length < 1)
        return;

      rngCsp.GetBytes(buf);
    }

    /// <summary>
    ///   Generates random numbers of the given size
    ///   and return the base 64 string.
    /// </summary>
    ///
    /// <returns> Base 64 string of the generated array. </returns>
    ///
    public static string GetBytes(int len)
    {
      if (len < 1)
      {
        throw new ArgumentException("Input length must be greater than 0");
      }

      byte[] b = new byte[len];

      rngCsp.GetBytes(b);

      return Convert.ToBase64String(b);
    }
  }
}
