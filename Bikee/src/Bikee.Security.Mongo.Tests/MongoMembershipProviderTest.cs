using System.Web.Security;
using FluentAssertions;
using NUnit.Framework;

namespace Bikee.Security.Mongo.Tests
{
	[TestFixture]
	public class MongoMembershipProviderTest
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
			this.provider.Database.Should().NotBeNull();
			this.provider.UsersCollection.Should().NotBeNull();
			this.provider.CollectionName.Should().NotBeNull();
		}

		[TestCase("User name", "email@mail.com", true)]
		public void CreateUserTest(string userName, string email, bool isApproved)
		{
			MembershipCreateStatus status;
			var user = this.provider.CreateUser(userName, "password_", email, string.Empty, string.Empty, isApproved, null, out status);

			Assert.That(status == MembershipCreateStatus.Success);
			user.Should().NotBeNull();

			Assert.That(user.UserName == userName);
			Assert.That(user.Email == email);
			Assert.That(user.IsApproved == isApproved);
		}
	}
}
