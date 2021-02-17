using System;

namespace Cryptool
{
  /// <summary>
  ///   Utils related to byte[] manipulation.
  /// </summary>
  ///
  public static class BufArray
  {
    /// <summary>
    ///   Retrieves arrya of bytes from base64 string.
    /// </summary>
    ///
    /// <param name="b64"></param>
    ///
    /// <returns> byte[] with decoded data on success, null otherwise. </returns>
    ///
    public static byte[] BufferFromB64(string b64)
    {
      try
      {
        return Convert.FromBase64String(b64);
      }
      catch (Exception)
      {
        return null;
      }
    }

    /// <summary>
    ///   Combines two arrays in one new array.
    /// </summary>
    ///
    /// <param name="first">
    ///   The first array, placed from indice 0 in the new array.
    /// </param>
    ///
    /// <param name="second">
    ///   The second array, placed from first.Length in the new array.
    /// </param>
    ///
    /// <returns> Combined array. </returns>
    public static byte[]
    Combine(byte[] first, byte[] second)
    {
      byte[] ret = new byte[first.Length + second.Length];
      Buffer.BlockCopy(first, 0, ret, 0, first.Length);
      Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
      return ret;
    }

    /// <summary>
    ///   Compare two arrays byte by byte, starting at
    ///   specified offset in arrays to be compared.
    /// </summary>
    ///
    /// <param name="first">
    ///   The first array.
    /// </param>
    ///
    /// <param name="firstOffset">
    ///   The offset where the comparison starts in the first array.
    /// </param>
    ///
    /// <param name="second">
    ///   The second array.
    /// </param>
    ///
    /// <param name="secondOffset">
    ///   The offset where the comparison starts in the second array.
    /// </param>
    ///
    /// <param name="len">
    ///   Length of the comparison.
    /// </param>
    ///
    /// <returns>
    ///   True if compared bytes are equal, false otherwise.
    /// </returns>
    public static bool
    Compare(byte[] first, int firstOffset,
            byte[] second, int secondOffset,
            int len)
    {
      if (len > (first.Length - firstOffset)
          || len > (second.Length - secondOffset))
      {
        return false;
      }

      for (int i = 0; i < len; i++)
      {
        if (first[firstOffset + i] != second[secondOffset + i])
        {
          return false;
        }
      }
      return true;
    }

    /// <summary>
    ///   Extracts subarray from input buffer.
    /// </summary>
    ///
    /// <param name="buf">  </param>
    ///
    /// <param name="offset">  </param>
    ///
    /// <param name="length">  </param>
    ///
    /// <returns> Subarray. </returns>
    public static byte[]
    SubArray(byte[] buf, int offset, int length)
    {
      byte[] r = new byte[length];
      System.Array.Copy(buf, offset, r, 0, length);
      return r;
    }


    /// <summary>
    ///   Wipes the given array filling it with 0.
    /// </summary>
    ///
    /// <param name="arr"></param>
    ///
    public static void
    Wipe0(byte[] arr)
    {
      for (int i = 0; i < arr.Length; i++)
      {
        arr[i] = 0;
      }
    }

  }
}
