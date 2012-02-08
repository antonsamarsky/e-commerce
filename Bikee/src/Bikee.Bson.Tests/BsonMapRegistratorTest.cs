using System.ComponentModel.Composition;
using FluentAssertions;
using MongoDB.Bson.Serialization;
using NUnit.Framework;

namespace Bikee.Bson.Tests
{
	[TestFixture]
	public class BsonMapRegistratorTest
	{
		[Test]
		public void ComposeTest()
		{
			BsonMapRegistrator.Compose();

			BsonClassMap.IsClassMapRegistered(typeof(TestDomainObject)).Should().BeTrue();
		}
	}

	[Export(typeof(IBsonMap))]
	public class TestDomainObjectMap :IBsonMap
	{
		public void Register()
		{
			if (BsonClassMap.IsClassMapRegistered(typeof (TestDomainObject)))
			{
				return;
			}

			BsonClassMap.RegisterClassMap<TestDomainObject>(cm => cm.AutoMap());
		}
	}

	public class TestDomainObject
	{
		public int Id;
		public string Name;
	}
}
