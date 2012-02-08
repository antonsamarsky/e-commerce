using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Web.Security;
using Bikee.Mongo.Tests;
using FluentAssertions;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
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
			this.provider.UserCollection.Should().NotBeNull();
		}

		[TestCase("User name", "barbar! _asvada", "email@mail.com", true)]
		public void CreateUserDefaultTest(string userName, string password, string email, bool isApproved)
		{
			MembershipCreateStatus status;
			var user = Membership.CreateUser(userName, password, email, null, null, isApproved, null, out status);

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
			var userFromDB = this.MongoDatabase.GetCollection<User>(this.provider.UserCollectionName).FindOneById(BsonValue.Create(user.ProviderUserKey));

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
				{"passwordFormat", format.ToString()}
			};
			mongoProvider.Initialize("MongoMembershipProvider", config);
		
			// create the user
			MembershipCreateStatus status;
			var user = mongoProvider.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
			status.Should().Be(MembershipCreateStatus.Success);
			user.Should().NotBeNull();

			// verify that the password format was saved
			var collection = this.MongoDatabase.GetCollection<User>(mongoProvider.UserCollectionName);
			var userFromDB = collection.FindOneById(BsonValue.Create(user.ProviderUserKey));
			userFromDB.PasswordFormat.Should().Be(format);

			// then attempt to verify the user
			mongoProvider.ValidateUser("foo", "barbar!").Should().BeTrue();
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
			Membership.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
			status.Should().Be(MembershipCreateStatus.Success);

			this.provider.DeleteUser("foo", true).Should().BeTrue();
			this.MongoDatabase.GetCollection<User>(this.provider.UserCollectionName).Count().Should().Be(0);

			this.provider.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
			status.Should().Be(MembershipCreateStatus.Success);

			// in Mongo, all associated data is stored in same document so 
			// passing true or false to DeleteUser will be the same.
			provider.DeleteUser("foo", deleteAllRelatedData: true).Should().BeTrue(); ;

			this.MongoDatabase.GetCollection<User>(this.provider.UserCollectionName).Count().Should().Be(0);
		}

		[Test]
		public void FindUsersByNameTest()
		{
			MembershipCreateStatus status;
			Membership.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
			Membership.CreateUser("foo2", "barbar2!", "foo2@bar.com", null, null, true, null, out status);

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
			Membership.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
			Membership.CreateUser("foo2", "barbar2!", "some@bar.com", null, null, true, null, out status);

			int records;
			MembershipUserCollection users = this.provider.FindUsersByEmail("foo", 0, 5, out records);
			records.Should().Be(1);
			users["foo"].Email.Should().Be("foo@bar.com");
		}

		[Test]
		public void CreateUserOverridesTest()
		{
			MembershipCreateStatus status;
			Membership.CreateUser("foo", "barbar!", "foo@bar.com", "question", "answer", true, out status);

			int records;
			MembershipUserCollection users = Membership.FindUsersByName("f", 0, 10, out records);
			records.Should().Be(1);
			users["foo"].UserName.Should().Be("foo");

			Membership.CreateUser("test", "barbar!", "myemail@host.com", "question", "answer", true, out status);
			users = Membership.FindUsersByName("t", 0, 10, out records);

			records.Should().Be(1);
			users["test"].UserName.Should().Be("test");
		}

		[Test]
		public void NumberOfUsersOnlineTest()
		{
			int numOnline = Membership.GetNumberOfUsersOnline();
			Assert.AreEqual(0, numOnline);

			MembershipCreateStatus status;
			Membership.CreateUser("foo", "barbar!", "foo@bar.com", "question", "answer", true, out status);
			Membership.CreateUser("foo2", "barbar!", "foo2@bar.com", "question", "answer", true, out status);

			numOnline = Membership.GetNumberOfUsersOnline();
			Assert.AreEqual(2, numOnline);
		}

		[Test]
		public void UnlockUserTest()
		{
			MembershipCreateStatus status;
			Membership.CreateUser("foo", "barbar!", "foo@bar.com", "question", "answer", true, out status);
			Assert.IsFalse(Membership.ValidateUser("foo", "bar2"));
			Assert.IsFalse(Membership.ValidateUser("foo", "bar3"));
			Assert.IsFalse(Membership.ValidateUser("foo", "bar3"));
			Assert.IsFalse(Membership.ValidateUser("foo", "bar3"));
			Assert.IsFalse(Membership.ValidateUser("foo", "bar3"));

			// the user should be locked now so the right password should fail
			Assert.IsFalse(Membership.ValidateUser("foo", "barbar!"));

			MembershipUser user = Membership.GetUser("foo");
			Assert.IsTrue(user.IsLockedOut);

			Assert.IsTrue(user.UnlockUser());
			user = Membership.GetUser("foo");
			Assert.IsFalse(user.IsLockedOut);

			Assert.IsTrue(Membership.ValidateUser("foo", "barbar!"));
		}

		[Test]
		public void GetUsernameByEmailTest()
		{
			MembershipCreateStatus status;
			Membership.CreateUser("foo", "barbar!", "foo@bar.com", "question", "answer", true, out status);
			string username = Membership.GetUserNameByEmail("foo@bar.com");
			Assert.AreEqual("foo", username);

			username = Membership.GetUserNameByEmail("foo@b.com");
			Assert.IsNull(username);

			username = Membership.GetUserNameByEmail("  foo@bar.com   ");
			Assert.AreEqual("foo", username);
		}

		[Test]
		public void UpdateUserTest()
		{
			MembershipCreateStatus status;
			Membership.CreateUser("foo", "barbar!", "foo@bar.com", "color", "blue", true, out status);
			Assert.AreEqual(MembershipCreateStatus.Success, status);

			MembershipUser user = Membership.GetUser("foo");

			user.Comment = "my comment";
			user.Email = "my email";
			user.IsApproved = false;
			user.LastActivityDate = new DateTime(2008, 1, 1);
			user.LastLoginDate = new DateTime(2008, 2, 1);
			Membership.UpdateUser(user);

			MembershipUser newUser = Membership.GetUser("foo");
			Assert.AreEqual(user.Comment, newUser.Comment);
			Assert.AreEqual(user.Email, newUser.Email);
			Assert.AreEqual(user.IsApproved, newUser.IsApproved);
			user.LastActivityDate.Should().BeWithin(new TimeSpan(0, 0, 0, 0)).After(newUser.LastActivityDate);
			Assert.AreEqual(user.LastLoginDate, newUser.LastLoginDate);
		}

		[Test]
		public void ChangePasswordQuestionAndAnswerTest()
		{
			MembershipCreateStatus status;
			Membership.CreateUser("foo", "barbar!", "foo@bar.com", "color", "blue", true, out status);
			Assert.AreEqual(MembershipCreateStatus.Success, status);

			MembershipUser user = Membership.GetUser("foo");
			Action act = () => user.ChangePasswordQuestionAndAnswer(string.Empty, "newQ", "newA");
			act.ShouldThrow<ArgumentException>();

			act = () => user.ChangePasswordQuestionAndAnswer("barbar!", string.Empty, "newA");
			act.ShouldThrow<ArgumentException>();

			act = () => user.ChangePasswordQuestionAndAnswer("barbar!", "newQ", string.Empty);
			act.ShouldThrow<ArgumentException>();

			act = () => user.ChangePasswordQuestionAndAnswer(null, "newQ", "newA");
			act.ShouldThrow<ArgumentNullException>();

			bool result = user.ChangePasswordQuestionAndAnswer("barbar!", "newQ", "newA");
			Assert.IsTrue(result);

			user = Membership.GetUser("foo");
			Assert.AreEqual("newQ", user.PasswordQuestion);
		}

		[Test]
		public void GetAllUsersTest()
		{
			MembershipCreateStatus status;
			// first create a bunch of users
			for (int i = 0; i < 100; i++)
			{
				var user = String.Format("foo{0}", i);
				Membership.CreateUser(user, "barbar!", user + "@bar.com", "question", "answer", true, out status);
			}

			MembershipUserCollection users = Membership.GetAllUsers();
			Assert.AreEqual(100, users.Count);
			int index = 0;
			foreach (MembershipUser user in users)
				Assert.AreEqual(String.Format("foo{0}", index++), user.UserName);

			int total;
			users = Membership.GetAllUsers(2, 10, out total);
			Assert.AreEqual(10, users.Count);
			Assert.AreEqual(100, total);
			index = 0;
			foreach (MembershipUser user in users)
				Assert.AreEqual(String.Format("foo2{0}", index++), user.UserName);
		}

		[TestCase(false, false, null)]
		[TestCase(false, true, null)]
		[TestCase(true, true, null)]
		[TestCase(true, true, "blue")]
		public void GetPasswordTest(bool requireQA, bool enablePasswordRetrieval, string answer)
		{
			MembershipCreateStatus status;

			var mongoProvider = new MongoMembershipProvider();
			var config = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"requiresQuestionAndAnswer", requireQA.ToString()},
				{"enablePasswordRetrieval", enablePasswordRetrieval.ToString()},
				{"passwordStrengthRegularExpression", "bar.*"},
				{"passwordFormat", MembershipPasswordFormat.Clear.ToString()},
				{"writeExceptionsToEventLog", bool.FalseString}
			};
			mongoProvider.Initialize("MongoMembershipProvider", config);

			mongoProvider.CreateUser("foo", "barbar!", "foo@bar.com", "color", "blue", true, null, out status);

			try
			{
				string password = mongoProvider.GetPassword("foo", answer);
				if (!enablePasswordRetrieval)
				{
					Assert.Fail("This should have thrown an exception");
				}
				Assert.AreEqual("barbar!", password);
			}
			catch (Exception)
			{
				if (requireQA && answer != null)
				{
					Assert.Fail("This should not have thrown an exception");
				}
			}
		}

		[Test]
		public void GetPasswordWithWrongAnswerTest()
		{
			MembershipCreateStatus status;
			var provider1 = new MongoMembershipProvider();
			var config = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"requiresQuestionAndAnswer", "true"},
				{"enablePasswordRetrieval", "true"},
				{"passwordFormat", "Encrypted"}
			};
			provider1.Initialize(null, config);
			provider1.CreateUser("foo", "barbar!", "foo@bar.com", "color", "blue", true, null, out status);

			var provider2 = new MongoMembershipProvider();
			NameValueCollection config2 = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"requiresQuestionAndAnswer", "true"},
				{"enablePasswordRetrieval", "true"},
				{"passwordFormat", "Encrypted"}
			};
			provider2.Initialize(null, config2);

			try
			{
				string pw = provider2.GetPassword("foo", "wrong");
				Assert.Fail("Should have  failed");
			}
			catch (MembershipPasswordException)
			{
			}
		}

		[Test]
		public void GetUserTest()
		{
			MembershipCreateStatus status;
			var guid = Guid.NewGuid();
			Membership.CreateUser("foo", "barbar!", "foo@bar.com", "question", "answer", true, guid, out status);
			MembershipUser user = Membership.GetUser(guid);
			Assert.AreEqual("foo", user.UserName);

			// now move the activity date back outside the login window
			user.LastActivityDate = new DateTime(2008, 1, 1);
			Membership.UpdateUser(user);

			user = Membership.GetUser("foo");
			Assert.IsFalse(user.IsOnline);

			user = Membership.GetUser("foo", true);
			Assert.IsTrue(user.IsOnline);

			// now move the activity date back outside the login
			// window again so we can test with providerUserKey
			user.LastActivityDate = new DateTime(2008, 1, 1);
			Membership.UpdateUser(user);

			user = Membership.GetUser(guid);
			Assert.IsFalse(user.IsOnline);

			user = Membership.GetUser(guid, true);
			Assert.IsTrue(user.IsOnline);
		}

		[Test]
		public void FindUsersTest()
		{
			MembershipCreateStatus status;
			for (int i = 0; i < 100; i++)
			{
				var user = String.Format("boo{0}", i);
				Membership.CreateUser(user, "barbar!", user + "@bar.com", "question", "answer", true, out status);
				Assert.AreEqual(MembershipCreateStatus.Success, status);
			}
			for (int i = 0; i < 100; i++)
			{
				var user = String.Format("foo{0}", i);
				Membership.CreateUser(user, "barbar!", user + "@bar.com", "question", "answer", true, null, out status);
				Assert.AreEqual(MembershipCreateStatus.Success, status);
			}
			for (int i = 0; i < 100; i++)
			{
				var user = String.Format("schmoo{0}", i);
				Membership.CreateUser(user, "barbar!", user + "@bar.com", "question", "answer", true, null, out status);
				Assert.AreEqual(MembershipCreateStatus.Success, status);
			}

			int total = 0;
			MembershipUserCollection users = Membership.FindUsersByName("fo");
			Assert.AreEqual(100, users.Count);

			users = Membership.FindUsersByName("fo", 2, 10, out total);
			Assert.AreEqual(10, users.Count);
			Assert.AreEqual(100, total);
			int index = 0;
			foreach (MembershipUser user in users)
				Assert.AreEqual(String.Format("foo2{0}", index++), user.UserName);
		}

		[Test]
		public void CreateUserWithNoQATest()
		{
			MembershipCreateStatus status;
			var mongoProvider = new MongoMembershipProvider();
			NameValueCollection config = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"requiresQuestionAndAnswer", bool.TrueString},
				{"passwordFormat", MembershipPasswordFormat.Clear.ToString()}
			};
			mongoProvider.Initialize(null, config);

			mongoProvider.CreateUser("foo", "barbar!", "foo@bar.com", "color", null, true, null, out status);
			Assert.AreEqual(MembershipCreateStatus.InvalidAnswer, status);


			mongoProvider.CreateUser("foo", "barbar!", "foo@bar.com", "", "blue", true, null, out status);
			Assert.AreEqual(MembershipCreateStatus.InvalidQuestion, status);
		}

		[Test]
		public void MinRequiredAlphaTest()
		{
			var mongoProvider = new MongoMembershipProvider();
			var config = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"minRequiredNonalphanumericCharacters", "3"}
			};
			mongoProvider.Initialize(null, config);

			MembershipCreateStatus status;
			MembershipUser user = mongoProvider.CreateUser("foo", "pw!pass", "email", null, null, true, null, out status);
			Assert.IsNull(user);
			Assert.AreEqual(MembershipCreateStatus.InvalidPassword, status);

			user = mongoProvider.CreateUser("foo", "pw!pa!!", "email", null, null, true, null, out status);
			Assert.IsNotNull(user);
			Assert.AreEqual(MembershipCreateStatus.Success, status);
		}

		[Test]
		public void GetPasswordWithNullValuesTest()
		{
			MembershipCreateStatus status;
			var mongoProvider = new MongoMembershipProvider();
			NameValueCollection config = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"requiresQuestionAndAnswer", "false"},
				{"enablePasswordRetrieval", "true"},
				{"passwordFormat", MembershipPasswordFormat.Clear.ToString()}
			};
			mongoProvider.Initialize(null, config);

			MembershipUser user = mongoProvider.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
			Assert.IsNotNull(user);

			string pw = mongoProvider.GetPassword("foo", null);
			Assert.AreEqual("barbar!", pw);
		}

		[Test]
		public void GetEncryptedPasswordTest()
		{
			MembershipCreateStatus status;
			var mongoProvider = new MongoMembershipProvider();
			NameValueCollection config = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"requiresQuestionAndAnswer", "false"},
				{"enablePasswordRetrieval", "true"},
				{"passwordFormat", MembershipPasswordFormat.Encrypted.ToString()}
			};
			mongoProvider.Initialize(null, config);

			MembershipUser user = mongoProvider.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
			Assert.IsNotNull(user);

			string pw = mongoProvider.GetPassword("foo", null);
			Assert.AreEqual("barbar!", pw);
		}

		[Test]
		public void CrossAppLoginTest()
		{
			var mongoProvider = new MongoMembershipProvider();

			NameValueCollection config = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"passwordStrengthRegularExpression", "bar.*"},
				{"passwordFormat", "Clear"}
			};
			mongoProvider.Initialize(null, config);
			MembershipCreateStatus status;
			mongoProvider.CreateUser("foo", "bar!bar", null, null, null, true, null, out status);

			var mongoProvider2 = new MongoMembershipProvider(); ;
			NameValueCollection config2 = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"passwordStrengthRegularExpression", ".*"},
				{"passwordFormat", "Clear"}
			};
			mongoProvider2.Initialize(null, config2);

			bool worked = mongoProvider2.ValidateUser("foo", "bar!bar");
			Assert.AreEqual(false, worked);

			this.MongoDatabase.DropCollection(mongoProvider2.UserCollectionName);
		}

		[Test]
		public void ResetPasswordTest()
		{
			var mongoProvider = new MongoMembershipProvider();

			NameValueCollection config = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"passwordStrengthRegularExpression", "bar.*"},
				{"passwordFormat", "Clear"},
				{"requiresQuestionAndAnswer", "false"}
			};
			mongoProvider.Initialize(null, config);

			MembershipCreateStatus status;
			mongoProvider.CreateUser("foo", "bar!bar", "foo@bar.com", null, null, true, null, out status);

			MembershipUser u = mongoProvider.GetUser("foo", false);
			string newpw = mongoProvider.ResetPassword("foo", null);
			newpw.Should().NotBeBlank();
		}

		[Test]
		public void ChangeAppNameTest()
		{
			var mongoProvider = new MongoMembershipProvider();
			NameValueCollection config = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"requiresUniqueEmail", "false"},
				{"passwordStrengthRegularExpression", "bar.*"},
				{"passwordFormat", "Clear"}
			};
			mongoProvider.Initialize(null, config);
			MembershipCreateStatus status;
			mongoProvider.CreateUser("foo", "bar!bar", "asd@sdfs.asd", null, null, true, null, out status);
			Assert.AreEqual(MembershipCreateStatus.Success, status);

			var provider2 = new MongoMembershipProvider();
			NameValueCollection config2 = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"requiresUniqueEmail", "false"},
				{"applicationName", "/myapp"},
				{"passwordStrengthRegularExpression", "foo.*"},
				{"passwordFormat", "Clear"}
			};
			provider2.Initialize(null, config2);
			provider2.CreateUser("foo2", "foo!foo", "asd@sdfs.asd", null, null, true, null, out status);
			Assert.AreEqual(MembershipCreateStatus.Success, status);

			mongoProvider.ApplicationName = "/myapp";
			Assert.IsFalse(mongoProvider.ValidateUser("foo", "bar!bar"));
			Assert.IsTrue(mongoProvider.ValidateUser("foo2", "foo!foo"));
		}

		[Test]
		public void GetUserLooksForExactUsernameTest()
		{
			MembershipCreateStatus status;
			Membership.CreateUser("code", "barbar!", "code@example.com", "question", "answer", true, out status);
			status.Should().Be(MembershipCreateStatus.Success);

			MembershipUser user = Membership.GetUser("code");
			Assert.AreEqual("code", user.UserName);

			user = Membership.GetUser("co_e");
			Assert.IsNull(user);
		}

		[Test]
		public void GetUserNameByEmailLooksForExactEmailTest()
		{
			MembershipCreateStatus status;
			Membership.CreateUser("code", "barbar!", "code@mysql.com", "question", "answer", true, out status);
			status.Should().Be(MembershipCreateStatus.Success);

			string username = Membership.GetUserNameByEmail("code@mysql.com");
			Assert.AreEqual("code", username);

			username = Membership.GetUserNameByEmail("co_e@mysql.com");
			Assert.IsNull(username);
		}

		[Test, Ignore]
		public void UserUpdateDoesNotWipeOutIgnoredFieldsTest()
		{
			if (!BsonClassMap.IsClassMapRegistered(typeof(Profile)))
			{
				BsonClassMap.RegisterClassMap<Profile>();
			}

			MembershipCreateStatus status;
			Membership.CreateUser("foo", "bar!bar", "foo@bar.com", null, null, true, out status);
			status.Should().Be(MembershipCreateStatus.Success);

			// ensure user created correctly
			var user = Membership.GetUser("foo");
			Assert.AreEqual("foo@bar.com", user.Email);

			// save Profile over User
			var profiles = this.MongoDatabase.GetCollection<Profile>(this.provider.UserCollectionName);

			var profile = profiles.FindOne();
			profile.FirstName = "Neo";

			profiles.Save(profile);

			// ensure profile saved correctly
			profile = profiles.FindOne();
			Assert.AreEqual("Neo", profile.FirstName);
			Assert.AreEqual("foo@bar.com", profile.Email);

			// validate User
			var valid = Membership.ValidateUser("foo", "bar!bar");
			Assert.AreEqual(true, valid);

			// ensure profile fields still in database
			profile = profiles.FindOne();
			//Assert.AreEqual("Neo", profile.FirstName);
			Assert.AreEqual("foo@bar.com", profile.Email);

			// update User
			user.ChangePassword("bar!bar", "bar*foo!foo");

			// ensure profile fields still in database
			profile = profiles.FindOne();
			//Assert.AreEqual("Neo", profile.FirstName);
			Assert.AreEqual("foo@bar.com", profile.Email);
		}

		public class Profile : User
		{
			public string FirstName { get; set; }
		}
	}
}
