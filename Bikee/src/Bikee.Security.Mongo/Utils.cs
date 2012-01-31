using System;
using System.Configuration.Provider;
using System.Linq.Expressions;
using System.Reflection;
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
		/// Encodes the password. Encrypts, Hashes, or leaves the password clear based on the PasswordFormat.
		/// </summary>
		/// <param name="stringToBeEncoded">The string to be encoded.</param>
		/// <param name="passwordFormatToUse">The password format to use.</param>
		/// <returns>
		/// The encoded password.
		/// </returns>
		public static string Encode(this string stringToBeEncoded, MembershipPasswordFormat passwordFormatToUse)
		{
			if (string.IsNullOrEmpty(stringToBeEncoded))
			{
				return null;
			}

			byte[] passwordData;
			string encodedString = stringToBeEncoded;
			switch (passwordFormatToUse)
			{
				case MembershipPasswordFormat.Clear:
					break;
				case MembershipPasswordFormat.Encrypted:
					passwordData = Encoding.Unicode.GetBytes(encodedString);
					encodedString = MachineKey.Encode(passwordData, MachineKeyProtection.All);
					break;
				case MembershipPasswordFormat.Hashed:
					passwordData = Encoding.Unicode.GetBytes(encodedString);
					encodedString = MachineKey.Encode(passwordData, MachineKeyProtection.Validation);
					break;
				default:
					throw new Exception("Unsupported password format.");
			}

			return encodedString;
		}

		/// <summary>
		/// TODO: Check if decode using HASH does not used with answer/question.
		/// Decodes the password. Decrypts or leaves the password clear based on the PasswordFormat.
		/// </summary>
		/// <param name="stringToBeDecoded">The string to be decoded.</param>
		/// <param name="passwordFormatToUse">The password format to use.</param>
		/// <returns>The decoded data.</returns>
		public static string Decode(this string stringToBeDecoded, MembershipPasswordFormat passwordFormatToUse)
		{
			string dencodedString = stringToBeDecoded;
			switch (passwordFormatToUse)
			{
				case MembershipPasswordFormat.Clear:
					break;
				case MembershipPasswordFormat.Encrypted:
					dencodedString = Encoding.Unicode.GetString(MachineKey.Decode(dencodedString, MachineKeyProtection.All));
					break;
				case MembershipPasswordFormat.Hashed:
					dencodedString = Encoding.Unicode.GetString(MachineKey.Decode(dencodedString, MachineKeyProtection.Validation));
					break;
				default:
					throw new ProviderException("Unsupported password format.");
			}

			return dencodedString;
		}
	}
}
