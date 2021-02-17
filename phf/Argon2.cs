using System;
using System.Linq;

using Konscious.Security.Cryptography;


namespace Cryptool
{

  /// <summary>
  ///
  /// </summary>
  public class Argon2Parameter
  {
    /// <summary>
    ///
    /// </summary>
    public int Parallelism;

    /// <summary>
    ///
    /// </summary>
    public int MemorySize1Kb;

    /// <summary>
    ///
    /// </summary>
    public int Iterations;

    /// <summary>
    ///
    /// </summary>
    public int ByteCount;

    /// <summary>
    ///
    /// </summary>
    public byte[] Salt;

    /// <summary>
    ///
    /// </summary>
    public byte[] Data;
  }


  /// <summary>
  ///   Argon2id.
  /// </summary>
  public static class Argon2
  {

    /// <summary>
    ///   Computes argon2id hash.
    /// </summary>
    /// <param name="password"></param>
    /// <param name="param"></param>
    /// <returns></returns>
    public static byte[]
    ComputeHash2id(byte[] password, Argon2Parameter param)
    {
      var a2id = new Argon2id(password);

      try
      {
        a2id.DegreeOfParallelism = param.Parallelism;
        a2id.MemorySize = param.MemorySize1Kb;
        a2id.Iterations = param.Iterations;
        a2id.AssociatedData = param.Data;

        a2id.Salt = param.Salt;

        return a2id.GetBytes(param.ByteCount);
      }
      catch (Exception)
      {
        return null;
      }
      finally
      {
        a2id.Dispose();
      }
    }


    /// <summary>
    ///   Verifies an argon2 hash.
    /// </summary>
    /// <param name="password"></param>
    /// <param name="hashCanditate"></param>
    /// <param name="param"></param>
    /// <returns></returns>
    public static bool
    VerifyHash2id(byte[] password, byte[] hashCanditate, Argon2Parameter param)
    {
      if (password == null || hashCanditate == null)
      {
        return false;
      }

      byte[] _hash = ComputeHash2id(password, param);

      if (_hash == null)
      {
        return false;
      }

      return _hash.SequenceEqual(hashCanditate);
    }

  }
}
