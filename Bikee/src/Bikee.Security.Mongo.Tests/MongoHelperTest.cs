using System;
using System.Collections.Generic;
using System.Web.Security;
using Bikee.Security.Domain;
using FluentAssertions;
using NUnit.Framework;

namespace Bikee.Security.Mongo.Tests
{
	[TestFixture]
	public class MongoHelperTest
	{
		[Test]
		public void GetElementNameForTest()
		{
			MongoHelper.GetElementNameFor<User>(u => u.Comment).Should().Be("Comment");
			MongoHelper.GetElementNameFor<User, DateTime>(u => u.CreationDate).Should().Be("CreationDate");
			MongoHelper.GetElementNameFor<User>(u => u.DisplayName).Should().Be("DisplayName");
			MongoHelper.GetElementNameFor<User>(u => u.Email).Should().Be("Email");
			MongoHelper.GetElementNameFor<User, int>(u => u.FailedPasswordAnswerAttemptCount).Should().Be("FailedPasswordAnswerAttemptCount");
			MongoHelper.GetElementNameFor<User, DateTime>(u => u.FailedPasswordAnswerAttemptWindowStart).Should().Be("FailedPasswordAnswerAttemptWindowStart");
			MongoHelper.GetElementNameFor<User, int>(u => u.FailedPasswordAttemptCount).Should().Be("FailedPasswordAttemptCount");
			MongoHelper.GetElementNameFor<User, DateTime>(u => u.FailedPasswordAttemptWindowStart).Should().Be("FailedPasswordAttemptWindowStart");
			MongoHelper.GetElementNameFor<User>(u => u.Id).Should().Be("_id");
			MongoHelper.GetElementNameFor<User, bool>(u => u.IsApproved).Should().Be("IsApproved");
			MongoHelper.GetElementNameFor<User, bool>(u => u.IsLockedOut).Should().Be("IsLockedOut");
			MongoHelper.GetElementNameFor<User, DateTime>(u => u.LastActivityDate).Should().Be("LastActivityDate");
			MongoHelper.GetElementNameFor<User, DateTime>(u => u.LastLockoutDate).Should().Be("LastLockoutDate");
			MongoHelper.GetElementNameFor<User, DateTime>(u => u.LastLoginDate).Should().Be("LastLoginDate");
			MongoHelper.GetElementNameFor<User, DateTime>(u => u.LastPasswordChangedDate).Should().Be("LastPasswordChangedDate");
			MongoHelper.GetElementNameFor<User>(u => u.LowercaseEmail).Should().Be("LowercaseEmail");
			MongoHelper.GetElementNameFor<User>(u => u.LowercaseUsername).Should().Be("LowercaseUsername");
			MongoHelper.GetElementNameFor<User>(u => u.Password).Should().Be("Password");
			MongoHelper.GetElementNameFor<User>(u => u.PasswordAnswer).Should().Be("PasswordAnswer");
			MongoHelper.GetElementNameFor<User, MembershipPasswordFormat>(u => u.PasswordFormat).Should().Be("PasswordFormat");
			MongoHelper.GetElementNameFor<User>(u => u.PasswordQuestion).Should().Be("PasswordQuestion");
			MongoHelper.GetElementNameFor<User, List<string>>(u => u.Roles).Should().Be("Roles");
			MongoHelper.GetElementNameFor<User>(u => u.UserName).Should().Be("UserName");
		}
	}
}