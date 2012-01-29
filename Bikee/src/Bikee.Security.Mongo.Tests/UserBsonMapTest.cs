using System;
using System.Web.Security;
using Bikee.Mongo.Tests;
using Bikee.Security.Domain;
using FluentAssertions;
using MongoDB.Bson;
using NUnit.Framework;

namespace Bikee.Security.Mongo.Tests
{
	[TestFixture]
	public class UserBsonMapTest : MongoTestBase
	{
		private User user;

		[SetUp]
		public void CreateUser()
		{
			this.user = new User
			{
				Id = ObjectId.GenerateNewId(),
				UserName = "UserName value",
				LowercaseUsername = "LowercaseUsername value",
				DisplayName = "DisplayName value",
				Email = "Email value",
				LowercaseEmail = "LowercaseEmail value",
				Password = "Password question",
				Comment = "Comment question",
				PasswordQuestion = "PasswordQuestion question",
				PasswordAnswer = "PasswordAnswer question",
				PasswordFormat = MembershipPasswordFormat.Clear,
				IsApproved = true,
				LastPasswordChangedDate = DateTime.MinValue,
				CreationDate = DateTime.MaxValue,
				IsLockedOut = false,
				LastLockoutDate = DateTime.MinValue,
				LastLoginDate = DateTime.MaxValue,
				LastActivityDate = DateTime.MaxValue,
				FailedPasswordAnswerAttemptCount = 0,
				FailedPasswordAnswerAttemptWindowStart = DateTime.MinValue,
				FailedPasswordAttemptCount = 0,
				FailedPasswordAttemptWindowStart = DateTime.MinValue
			};
		}

		[Test]
		public void MapTest()
		{
			// Register map
			new UserBsonMap();

			// Create collection
			var users = this.MongoDatabase.GetCollection<User>("users");

			// Insert user
			users.Insert(this.user);

			// Getuser
			var userFromDB = users.FindOne();

			// Assert if user is the same.
			userFromDB.ShouldHave().AllProperties().EqualTo(this.user);
		}
	}
}