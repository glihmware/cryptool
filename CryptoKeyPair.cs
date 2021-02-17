using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace Cryptool
{
  /// <summary>
  ///
  /// </summary>
  public class CryptoKeyPair
  {
    /// <summary>
    ///
    /// </summary>
    public byte[] Prv;

    /// <summary>
    ///
    /// </summary>
    public byte[] Pub;

    /// <summary>
    ///
    /// </summary>
    public int KeySize;

    /// <summary>
    ///
    /// </summary>
    public CryptoKeyPair()
    {

    }

    /// <summary>
    ///   Constructs from keys.
    /// </summary>
    /// <param name="keySize"></param>
    /// <param name="prv"></param>
    /// <param name="pub"></param>
    public CryptoKeyPair(int keySize, byte[] prv, byte[] pub)
    {
      this.KeySize = keySize;
      this.Prv = prv;
      this.Pub = pub;
    }

    /// <summary>
    ///   Constructs from base64 string keys.
    /// </summary>
    /// <param name="keySize"></param>
    /// <param name="prv"></param>
    /// <param name="pub"></param>
    public CryptoKeyPair(int keySize, string prv, string pub)
    {
      this.KeySize = keySize;
      this.Prv = Convert.FromBase64String(prv);
      this.Pub = Convert.FromBase64String(pub);
    }

    /// <summary>
    ///
    /// </summary>
    /// <returns></returns>
    public override string ToString()
    {
      (string Prv, string Pub) keys = this.GetBase64Pair();
      return $"CryptoKeyPair:\n[Prv]:'{keys.Prv}'\n[Pub]:'{keys.Pub}'";
    }


    /// <summary>
    ///   Computes the concatenated form of the CryptoKeyPair.
    /// </summary>
    /// <returns></returns>
    public string ConcatKeysB64()
    {
      (string Prv, string Pub) keys = this.GetBase64Pair();
      return $"{keys.Prv}|{keys.Pub}";
    }

    /// <summary>
    ///   Builds a CryptoKeyPair from it's concatenated form.
    /// </summary>
    /// <param name="concatKeys"></param>
    /// <param name="keySize"></param>
    /// <returns></returns>
    public static CryptoKeyPair
    FromConcatKeysB64(string concatKeys, int keySize)
    {
      try
      {
        string[] s = concatKeys.Split('|', StringSplitOptions.RemoveEmptyEntries);
        return new CryptoKeyPair(keySize, s[0], s[1]);
      }
      catch (Exception)
      {
        return null;
      }
    }

    /// <summary>
    ///   Computes the base64 string for each Prv and Pub keys.
    /// </summary>
    /// <returns></returns>
    public (string Prv, string Pub)
    GetBase64Pair()
    {
      return (Convert.ToBase64String(this.Prv), Convert.ToBase64String(this.Pub));
    }
  }
}
