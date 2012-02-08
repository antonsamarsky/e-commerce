using System.Configuration;
using Bikee.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Conventions;
using MongoDB.Bson.Serialization.Options;
using MongoDB.Driver;
using NUnit.Framework;

namespace Bikee.Mongo.Tests
{
	[TestFixture]
	public abstract class MongoTestBase
	{
		protected MongoServer MongoServer { get; set; }
		protected MongoDatabase MongoDatabase { get; set; }

		[SetUp]
		public void InitTestDatabase()
		{
			var conventions = new ConventionProfile();
			conventions.SetIgnoreExtraElementsConvention(new AlwaysIgnoreExtraElementsConvention());
			BsonClassMap.RegisterConventions(conventions, t => t.FullName.StartsWith("Bikee."));

			// Compose all maps.
			BsonMapRegistrator.Compose();

			string connectionString = ConfigurationManager.ConnectionStrings[0].ConnectionString;
			this.MongoServer = string.IsNullOrEmpty(connectionString)
												? MongoServer.Create() // connect to local host
												: MongoServer.Create(connectionString);

			string databaseName = ConfigurationManager.AppSettings["testDatabaseName"] ?? "bikee_test";
			if (this.MongoServer.DatabaseExists(databaseName))
			{
				this.MongoServer.DropDatabase(databaseName);
			}

			this.MongoDatabase = this.MongoServer.GetDatabase(databaseName);

			DateTimeSerializationOptions.Defaults = DateTimeSerializationOptions.LocalInstance;
		}

		[TearDown]
		public void DropTestDatabase()
		{
			this.MongoDatabase.Drop();
			this.MongoServer.Disconnect();
		}
	}
}
