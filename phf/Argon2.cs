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
    public int BitCount;

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
      using (var a2id = new Argon2id(password))
      {
        a2id.DegreeOfParallelism = param.Parallelism;
        a2id.MemorySize = param.MemorySize1Kb;
        a2id.Iterations = param.Iterations;
        a2id.AssociatedData = param.Data;

        a2id.Salt = param.Salt;

        return a2id.GetBytes(param.BitCount);
      }
    }


    /// <summary>
    ///   Verifies an argon2 hash.
    /// </summary>
    /// <param name="password"></param>
    /// <param name="param"></param>
    /// <param name="hash"></param>
    /// <returns></returns>
    public static bool
    VerifyHash2id(byte[] password, Argon2Parameter param, byte[] hash)
    {
      byte[] _hash = ComputeHash2id(password, param);
      return _hash.SequenceEqual(hash);
    }



  }
}
