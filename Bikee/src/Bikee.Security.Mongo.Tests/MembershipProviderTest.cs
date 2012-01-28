using System.Web.Security;
using FluentAssertions;
using NUnit.Framework;

namespace Bikee.Security.Mongo.Tests
{
	[TestFixture]
	public class MembershipProviderTest
	{
		private MembershipProvider provider;

		[SetUp]
		public void Init()
		{
			this.provider = (MembershipProvider)Membership.Provider;
		}

		[Test]
		public void InitTest()
		{
			this.provider.Should().NotBeNull();
			this.provider.Database.Should().NotBeNull();
			this.provider.ElementNames.Should().NotBeNull();
			this.provider.CollectionName.Should().NotBeNull();
		}
	}
}
