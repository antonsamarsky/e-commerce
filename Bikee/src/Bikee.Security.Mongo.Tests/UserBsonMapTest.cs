using System;
using System.Configuration;
using System.Web.Security;
using Bikee.Security.Domain;
using MongoDB.Driver;
using NUnit.Framework;

namespace Bikee.Security.Mongo.Tests
{
	[TestFixture]
	public class UserBsonMapTest
	{
		private User user;

		[SetUp]
		public void CreateUser()
		{
			this.user = new User
			{
				Username = "Username value",
				LowercaseUsername = "LowercaseUsername value",
				DisplayName = "DisplayName value",
				Email = "Email value",
				LowercaseEmail = "LowercaseEmail value",
				Password = "Password question",
				Comment = "Comment question",
				PasswordQuestion = "PasswordQuestion question",
				PasswordAnswer = "PasswordAnswer question",
				PasswordFormat = MembershipPasswordFormat.Clear,
				PasswordSalt = "PasswordSalt value",
				IsApproved = true,
				LastPasswordChangedDate = DateTime.MinValue,
				CreateDate = DateTime.Now,
				IsLockedOut = false,
				LastLockedOutDate = DateTime.MinValue,
				LastLoginDate = DateTime.Now,
				LastActivityDate = DateTime.Now,
				FailedPasswordAnswerAttemptCount = 0,
				FailedPasswordAnswerAttemptWindowStart = DateTime.MinValue,
				FailedPasswordAttemptCount = 0,
				FailedPasswordAttemptWindowStart = DateTime.MinValue
			};
		}

		[Test]
		public void Map()
		{
			new UserBsonMap();
			MongoServer server = MongoServer.Create(); // connect to localhost
			MongoDatabase database = server.GetDatabase("bikee");
			var users = database.GetCollection<User>("users");
			users.Insert(this.user);
		}
	}
}