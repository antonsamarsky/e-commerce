using System.Web.Security;
using Bikee.Mongo.Tests;
using FluentAssertions;
using NUnit.Framework;

namespace Bikee.Security.Mongo.Tests
{
	[TestFixture]
	public class MongoMembershipProviderTest : MongoTestBase
	{
		private MongoMembershipProvider provider;

		[SetUp]
		public void Init()
		{
			this.provider = (MongoMembershipProvider)Membership.Provider;
		}

		[Test]
		public void InitTest()
		{
			this.provider.Should().NotBeNull();
			this.provider.UsersCollection.Should().NotBeNull();
		}

		[TestCase("User name", "email@mail.com", true)]
		public void CreateUserTest(string userName, string email, bool isApproved)
		{
			MembershipCreateStatus status;
			var user = this.provider.CreateUser(userName, "password_", email, null, null, isApproved, null, out status);

			status.Should().Be(MembershipCreateStatus.Success);
			user.Should().NotBeNull();

			Assert.That(user.UserName == userName);
			Assert.That(user.Email == email);
			Assert.That(user.IsApproved == isApproved);
		}
	}
}
