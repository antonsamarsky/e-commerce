using System;
using System.Web.Security;
using Bikee.Mongo.Tests;
using FluentAssertions;
using MongoDB.Bson;
using NUnit.Framework;

namespace Bikee.Security.Mongo.Tests
{
	[TestFixture]
	public class UserBsonMapTest : MongoTestBase
	{
		[Test]
		public void MapTest()
		{
			var user = new User
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

			// Create collection
			var users = this.MongoDatabase.GetCollection<User>("users");

			// Insert user
			users.Insert(user);

			// Getuser
			var userFromDB = users.FindOne();

			// Assert if user is the same.
			userFromDB.ShouldHave().AllProperties().EqualTo(user);
		}
	}
}