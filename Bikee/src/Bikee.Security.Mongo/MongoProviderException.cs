using System;
using System.Configuration.Provider;

namespace Bikee.Security.Mongo
{
	public class MongoProviderException : ProviderException
	{
		public MongoProviderException(string message) : base(message)
		{
		}

		public MongoProviderException(string message, Exception exception) : base(message, exception)
		{
		}

		public MongoProviderException(Exception exception) : base(exception.Message, exception)
		{
		}
	}
}