using System;
using System.Security.Cryptography;
using System.Text;

namespace Bikee.Security.Domain
{
	/// <summary>
	/// http://msdn.microsoft.com/en-us/magazine/cc164107.aspx
	/// </summary>
	public sealed class SaltedHash
	{
		private const int saltLength = 6;

		private readonly string salt;
		private readonly string hash;
		private readonly HashAlgorithm hashAlgorithm;

		public string Salt { get { return this.salt; } }

		public string Hash { get { return this.hash; } }

		public static SaltedHash Create(string password, HashAlgorithm hashAlgorithm)
		{
			string salt = CreateSalt();
			string hash = CalculateHash(salt, password, hashAlgorithm);
			return new SaltedHash(salt, hash, hashAlgorithm);
		}

		public static SaltedHash Create(string salt, string hash, HashAlgorithm hashAlgorithm)
		{
			return new SaltedHash(salt, hash, hashAlgorithm);
		}

		public bool Verify(string password)
		{
			string h = CalculateHash(salt, password, this.hashAlgorithm);
			return this.hash.Equals(h);
		}

		private SaltedHash(string salt, string hash, HashAlgorithm hashAlgorithm)
		{
			this.salt = salt;
			this.hash = hash;
			this.hashAlgorithm = hashAlgorithm;
		}

		private static string CreateSalt()
		{
			byte[] r = CreateRandomBytes(saltLength);
			return Convert.ToBase64String(r);
		}

		private static byte[] CreateRandomBytes(int len)
		{
			var r = new byte[len];
			new RNGCryptoServiceProvider().GetBytes(r);
			return r;
		}

		private static string CalculateHash(string salt, string password, HashAlgorithm hashAlgorithm)
		{
			byte[] data = Encoding.UTF8.GetBytes(salt + password);
			byte[] hash = hashAlgorithm.ComputeHash(data);

			return Convert.ToBase64String(hash);
		}
	}
}