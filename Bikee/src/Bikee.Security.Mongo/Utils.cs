using System;
using System.Linq.Expressions;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Web.Security;
using MongoDB.Bson.Serialization;

namespace Bikee.Security.Mongo
{
	public static class Utils
	{
		public static T GetConfigValue<T>(string configValue, T defaultValue)
		{
			if (string.IsNullOrEmpty(configValue))
			{
				return defaultValue;
			}

			return ((T)Convert.ChangeType(configValue, typeof(T)));
		}

		public static string GetElementNameFor<TSource>(Expression<Func<TSource, object>> propertyLambda)
		{
			return GetElementNameFor<TSource, object>(propertyLambda);
		}

		/// <summary>
		/// Reference:
		/// http://stackoverflow.com/questions/671968/retrieving-property-name-from-lambda-expression
		/// </summary>
		public static string GetElementNameFor<TSource, TProperty>(Expression<Func<TSource, TProperty>> propertyLambda)
		{
			Type type = typeof(TSource);

			var member = propertyLambda.Body as MemberExpression;
			if (member == null)
			{
				throw new ArgumentException(string.Format("Expression '{0}' refers to a method, not a property.", propertyLambda));
			}

			var propInfo = member.Member as PropertyInfo;
			if (propInfo == null)
			{
				throw new ArgumentException(string.Format("Expression '{0}' refers to a field, not a property.", propertyLambda));
			}

			if (type != propInfo.ReflectedType && !type.IsSubclassOf(propInfo.ReflectedType))
			{
				throw new ArgumentException(string.Format("Expresion '{0}' refers to a property that is not from type {1}.", propertyLambda, type));
			}

			var map = BsonClassMap.LookupClassMap(typeof(TSource));
			if (map == null)
			{
				throw new ArgumentException(string.Format("Missing BsonClassMap for type {0}", type));
			}

			var memberMap = map.GetMemberMap(propInfo.Name);
			if (null == memberMap)
			{
				throw new ArgumentException(string.Format("BsonClassMap for type {0} does not contain a mapping for member {1}", type, propInfo.Name));
			}

			return memberMap.ElementName;
		}

		/// <summary>
		/// Encodes the specified string to be encoded.
		/// </summary>
		/// <param name="stringToBeEncoded">The string to be encoded.</param>
		/// <param name="passwordFormatToUse">The password format to use.</param>
		/// <returns></returns>
		public static string Encode(this string stringToBeEncoded, MembershipPasswordFormat passwordFormatToUse = MembershipPasswordFormat.Encrypted)
		{
			string salt;
			return stringToBeEncoded.Encode(out salt, passwordFormatToUse);
		}

		/// <summary>
		/// Encodes the password. Encrypts, Hashes, or leaves the password clear based on the PasswordFormat.
		/// </summary>
		/// <param name="stringToBeEncoded">The string to be encoded.</param>
		/// <param name="passwordFormatToUse">The password format to use.</param>
		/// <param name="salt">The salt.</param>
		/// <returns>
		/// The encoded password.
		/// </returns>
		public static string Encode(this string stringToBeEncoded, out string salt, MembershipPasswordFormat passwordFormatToUse = MembershipPasswordFormat.Encrypted)
		{
			salt = null;
			if (string.IsNullOrEmpty(stringToBeEncoded))
			{
				return null;
			}

			switch (passwordFormatToUse)
			{
				case MembershipPasswordFormat.Clear:
					return stringToBeEncoded;
				case MembershipPasswordFormat.Encrypted:
					var unicodeArrayToEncrypt = Encoding.Unicode.GetBytes(stringToBeEncoded);
					return MachineKey.Encode(unicodeArrayToEncrypt, MachineKeyProtection.All);
				case MembershipPasswordFormat.Hashed:
					var saltedHash = SaltedHash.Create(stringToBeEncoded, HashAlgorithm.Create("SHA512"));
					salt = saltedHash.Salt;
					return saltedHash.Hash;
				default:
					throw new MembershipPasswordException("Unsupported password format.");
			}
		}

		/// <summary>
		/// TODO: Check if decode using HASH does not used with answer/question.
		/// Decodes the password. Decrypts or leaves the password clear based on the PasswordFormat.
		/// </summary>
		/// <param name="stringToBeDecoded">The string to be decoded.</param>
		/// <param name="passwordFormatToUse">The password format to use.</param>
		/// <returns>
		/// The decoded data.
		/// </returns>
		public static string Decode(this string stringToBeDecoded, MembershipPasswordFormat passwordFormatToUse = MembershipPasswordFormat.Encrypted)
		{
			switch (passwordFormatToUse)
			{
				case MembershipPasswordFormat.Clear:
					return stringToBeDecoded;
				case MembershipPasswordFormat.Encrypted:
					var decoded = MachineKey.Decode(stringToBeDecoded, MachineKeyProtection.All);
					return Encoding.Unicode.GetString(decoded);
				case MembershipPasswordFormat.Hashed:
					throw new MembershipPasswordException("Cannot decode a hashed password.");
				default:
					throw new MembershipPasswordException("Unsupported password format.");
			}
		}

		/// <summary>
		/// Checks the specified password.
		/// </summary>
		/// <param name="password">The password.</param>
		/// <param name="correctPassword">The correct password.</param>
		/// <param name="salt">The salt.</param>
		/// <param name="passwordFormat">The password format.</param>
		/// <returns></returns>
		public static bool VerifyPassword(this string password, string correctPassword, MembershipPasswordFormat passwordFormat = MembershipPasswordFormat.Encrypted, string salt = null)
		{
			switch (passwordFormat)
			{
				case MembershipPasswordFormat.Encrypted:
					var correct = Decode(correctPassword);
					return correct == password;
				case MembershipPasswordFormat.Hashed:
					var saltedHash = SaltedHash.Create(salt, correctPassword, HashAlgorithm.Create("SHA512"));
					return saltedHash.Verify(password);
				default:
					return password == correctPassword;
			}
		}
	}
}
