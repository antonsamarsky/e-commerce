﻿using System.Configuration;
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

		[TestFixtureSetUp]
		public void InitTestDatabase()
		{
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

		[TestFixtureTearDown]
		public void DropTestDatabase()
		{
			this.MongoDatabase.Drop();
			this.MongoServer.Disconnect();
		}
	}
}