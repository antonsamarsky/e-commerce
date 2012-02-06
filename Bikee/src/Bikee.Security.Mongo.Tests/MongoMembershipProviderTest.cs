using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Web.Security;
using Bikee.Mongo.Tests;
using FluentAssertions;
using MongoDB.Bson;
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

		[TestCase("User name", "barbar! _asvada", "email@mail.com", true)]
		public void CreateUserDefaultTest(string userName, string password, string email, bool isApproved)
		{
			MembershipCreateStatus status;
			var user = this.provider.CreateUser(userName, password, email, null, null, isApproved, null, out status);

			status.Should().Be(MembershipCreateStatus.Success);
			user.Should().NotBeNull();

			user.UserName.Should().Be(userName);
			user.Email.Should().Be(email);
			user.IsApproved.Should().Be(isApproved);
			user.LastLoginDate.Should().BeWithin(new TimeSpan(1, 0, 0, 0)).After(DateTime.MinValue);
			user.LastLockoutDate.Should().BeWithin(new TimeSpan(1, 0, 0, 0)).After(DateTime.MinValue);
			user.LastPasswordChangedDate.Should().BeWithin(new TimeSpan(1, 0, 0, 0)).After(DateTime.MinValue);
			user.LastActivityDate.Should().BeWithin(new TimeSpan(0, 0, 0, 1)).After(DateTime.Now);
			user.IsLockedOut.Should().Be(false);
			user.PasswordQuestion.Should().BeNull();
			user.Comment.Should().BeNull();
			user.ProviderUserKey.Should().NotBeNull();

			user.IsOnline.Should().Be(true);

			// Assert user information from database
			var userFromDB = this.MongoDatabase.GetCollection<User>(this.provider.UsersCollectionName).FindOneById(BsonValue.Create(user.ProviderUserKey));

			userFromDB.Should().NotBeNull();
			userFromDB.LowercaseUsername.Should().Be(userName.ToLowerInvariant());
			userFromDB.Email.Should().Be(email.ToLowerInvariant());
			userFromDB.Password.Should().NotBeEmpty();
			userFromDB.PasswordAnswer.Should().BeNull();
			userFromDB.PasswordFormat.Should().Be(MembershipPasswordFormat.Hashed);
			userFromDB.Roles.Should().BeEmpty();
			userFromDB.FailedPasswordAnswerAttemptCount.Should().Be(0);
			userFromDB.FailedPasswordAttemptCount.Should().Be(0);
			userFromDB.FailedPasswordAnswerAttemptWindowStart.Should().BeWithin(new TimeSpan(1, 0, 0, 0)).After(DateTime.MinValue);
			userFromDB.FailedPasswordAttemptWindowStart.Should().BeWithin(new TimeSpan(1, 0, 0, 0)).After(DateTime.MinValue);
		}

		[TestCase(MembershipPasswordFormat.Hashed)]
		[TestCase(MembershipPasswordFormat.Encrypted)]
		[TestCase(MembershipPasswordFormat.Clear)]
		public void CreateUserWithFormat(MembershipPasswordFormat format)
		{
			var mongoProvider = new MongoMembershipProvider();
			var config = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"passwordStrengthRegularExpression", "bar.*"},
				{"passwordFormat", format.ToString()}
			};
			mongoProvider.Initialize("MongoMembershipProvider", config);
			var username = "foo";
			var password = "barbar! _asvadasdfasf4r2423rfewQ!@$!@%&%^879s";

			// create the user
			MembershipCreateStatus status;
			var user = mongoProvider.CreateUser(username, password, "foo@bar.com", null, null, true, null, out status);
			status.Should().Be(MembershipCreateStatus.Success);

			// verify that the password format was saved
			var userFromDB = this.MongoDatabase.GetCollection<User>(mongoProvider.UsersCollectionName).FindOneById(BsonValue.Create(user.ProviderUserKey));
			userFromDB.PasswordFormat.Should().Be(format);

			// then attempt to verify the user
			provider.ValidateUser(username, password).Should().BeTrue();
		}

		[Test]
		public void ChangePasswordValidationTest()
		{
			// Create user with hashed password
			MembershipCreateStatus status;
			this.provider.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
			status.Should().Be(MembershipCreateStatus.Success);

			Action act = () => this.provider.ChangePassword("foo", "barbar!", "bar2");
			act.ShouldThrow<ArgumentException>().And.Message.Should().Be("Password is not valid.");

			Action act2 = () => this.provider.ChangePassword("foo", "barbar!", "barbar2");
			act2.ShouldThrow<ArgumentException>().And.Message.Should().Be("Password does not have required non-alphanumeric characters.");

			Action act3 = () => this.provider.ChangePassword("foo", "barbar!", "zzzxxx!");
			act3.ShouldThrow<ArgumentException>().And.Message.Should().Be("Password is not strong enough.");

			this.provider.ChangePassword("foo", "barbar!", "barfoo!").Should().BeTrue();
			this.provider.ValidateUser("foo", "barfoo!").Should().BeTrue();
		}

		[Test]
		public void CreateUserWithErrorsTest()
		{
			var mongoProvider = new MongoMembershipProvider();
			var config = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"passwordStrengthRegularExpression", "bar.*"},
				{"passwordFormat", MembershipPasswordFormat.Hashed.ToString()}
			};
			mongoProvider.Initialize("MongoMembershipProvider", config);

			// first try to create a user with a password not long enough
			MembershipCreateStatus status;
			MembershipUser user = provider.CreateUser("foo", "xyz", "foo@bar.com", null, null, true, null, out status);
			status.Should().Be(MembershipCreateStatus.InvalidPassword);
			user.Should().BeNull();

			// now with not enough non-alphas
			user = provider.CreateUser("foo", "xyz1234", "foo@bar.com", null, null, true, null, out status);
			status.Should().Be(MembershipCreateStatus.InvalidPassword);
			user.Should().BeNull();

			// now one that doesn't pass the regex test
			user = provider.CreateUser("foo", "xyzxyz!", "foo@bar.com", null, null, true, null, out status);
			status.Should().Be(MembershipCreateStatus.InvalidPassword);
			user.Should().BeNull();

			// now one that works
			user = provider.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
			status.Should().Be(MembershipCreateStatus.Success);
			user.Should().NotBeNull();
		}

		[Test]
		public void CreateUserWithDefaultInvalidCharactersTest()
		{
			// Username
			MembershipCreateStatus status;
			MembershipUser user = Membership.CreateUser("foo,", "barbar!", "foo@bar.com", null, null, true, null, out status);
			status.Should().Be(MembershipCreateStatus.InvalidUserName);
			user.Should().BeNull();

			user = Membership.CreateUser("foo%", "barbar!", "foo@bar.com", null, null, true, null, out status);
			status.Should().Be(MembershipCreateStatus.InvalidUserName);
			user.Should().BeNull();

			// Email
			user = Membership.CreateUser("foo", "barbar!", "foo,@bar.com", null, null, true, null, out status);
			status.Should().Be(MembershipCreateStatus.InvalidEmail);
			user.Should().BeNull();

			user = Membership.CreateUser("foo", "barbar!", "foo%@bar.com", null, null, true, null, out status);
			status.Should().Be(MembershipCreateStatus.InvalidEmail);
			user.Should().BeNull();
		}

		[TestCase("()-#", "^/`")]
		public void CreateUserWithCustomInvalidCharactersTest(string invalidUserChars, string invalidEmailChars)
		{
			var mongoProvider = new MongoMembershipProvider();
			var config = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"passwordStrengthRegularExpression", "bar.*"},
				{"passwordFormat", MembershipPasswordFormat.Hashed.ToString()},
				{"invalidUsernameCharacters", invalidUserChars}, 
				{"invalidEmailCharacters", invalidEmailChars}

			};
			mongoProvider.Initialize("MongoMembershipProvider", config);

			// Username
			MembershipCreateStatus status;
			var username = "foo{0}";
			foreach (var c in invalidUserChars.Split())
			{
				MembershipUser user = mongoProvider.CreateUser(string.Format(username, c), "barbar!", "foo@bar.com", null, null, true, null, out status);
				status.Should().Be(MembershipCreateStatus.InvalidUserName);
				user.Should().BeNull();
			}

			// Email
			var email = "foo{0}@bar.com";
			foreach (var c in invalidEmailChars.Split())
			{
				MembershipUser user = provider.CreateUser("foo", "barbar!", string.Format(email, c), null, null, true, null, out status);
				status.Should().Be(MembershipCreateStatus.InvalidEmail);
				user.Should().BeNull();
			}
		}

		[Test]
		public void DeleteUserTest()
		{
			MembershipCreateStatus status;
			this.provider.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
			status.Should().Be(MembershipCreateStatus.Success);

			this.provider.DeleteUser("foo", true).Should().BeTrue();
			this.MongoDatabase.GetCollection<User>(this.provider.UsersCollectionName).Count().Should().Be(0);

			this.provider.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
			status.Should().Be(MembershipCreateStatus.Success);

			// in Mongo, all associated data is stored in same document so 
			// passing true or false to DeleteUser will be the same.
			provider.DeleteUser("foo", deleteAllRelatedData: true).Should().BeTrue(); ;

			this.MongoDatabase.GetCollection<User>(this.provider.UsersCollectionName).Count().Should().Be(0);
		}

		[Test]
		public void FindUsersByNameTest()
		{
			MembershipCreateStatus status;
			this.provider.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
			this.provider.CreateUser("foo2", "barbar2!", "foo2@bar.com", null, null, true, null, out status);

			int records;
			MembershipUserCollection users = this.provider.FindUsersByName("f", 0, 10, out records);
			records.Should().Be(2);
			users["foo"].UserName.Should().Be("foo");
			users["foo2"].UserName.Should().Be("foo2");
		}

		[Test]
		public void FindUsersByEmailTest()
		{
			MembershipCreateStatus status;
			this.provider.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
			this.provider.CreateUser("foo2", "barbar2!", "some@bar.com", null, null, true, null, out status);

			int records;
			MembershipUserCollection users = this.provider.FindUsersByEmail("foo", 0, 5, out records);
			records.Should().Be(1);
			users["foo"].Email.Should().Be("foo@bar.com");
		}
	}
}
