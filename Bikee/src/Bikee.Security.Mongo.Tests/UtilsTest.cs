using System;
using System.Collections.Generic;
using System.Web.Security;
using Bikee.Security.Domain;
using FluentAssertions;
using NUnit.Framework;

namespace Bikee.Security.Mongo.Tests
{
	[TestFixture]
	public class UtilsTest
	{
		[Test]
		public void GetElementNameForTest()
		{
			Utils.GetElementNameFor<User>(u => u.Comment).Should().Be("Comment");
			Utils.GetElementNameFor<User, DateTime>(u => u.CreationDate).Should().Be("CreationDate");
			Utils.GetElementNameFor<User>(u => u.DisplayName).Should().Be("DisplayName");
			Utils.GetElementNameFor<User>(u => u.Email).Should().Be("Email");
			Utils.GetElementNameFor<User, int>(u => u.FailedPasswordAnswerAttemptCount).Should().Be("FailedPasswordAnswerAttemptCount");
			Utils.GetElementNameFor<User, DateTime>(u => u.FailedPasswordAnswerAttemptWindowStart).Should().Be("FailedPasswordAnswerAttemptWindowStart");
			Utils.GetElementNameFor<User, int>(u => u.FailedPasswordAttemptCount).Should().Be("FailedPasswordAttemptCount");
			Utils.GetElementNameFor<User, DateTime>(u => u.FailedPasswordAttemptWindowStart).Should().Be("FailedPasswordAttemptWindowStart");
			Utils.GetElementNameFor<User>(u => u.Id).Should().Be("_id");
			Utils.GetElementNameFor<User, bool>(u => u.IsApproved).Should().Be("IsApproved");
			Utils.GetElementNameFor<User, bool>(u => u.IsLockedOut).Should().Be("IsLockedOut");
			Utils.GetElementNameFor<User, DateTime>(u => u.LastActivityDate).Should().Be("LastActivityDate");
			Utils.GetElementNameFor<User, DateTime>(u => u.LastLockoutDate).Should().Be("LastLockoutDate");
			Utils.GetElementNameFor<User, DateTime>(u => u.LastLoginDate).Should().Be("LastLoginDate");
			Utils.GetElementNameFor<User, DateTime>(u => u.LastPasswordChangedDate).Should().Be("LastPasswordChangedDate");
			Utils.GetElementNameFor<User>(u => u.LowercaseEmail).Should().Be("LowercaseEmail");
			Utils.GetElementNameFor<User>(u => u.LowercaseUsername).Should().Be("LowercaseUsername");
			Utils.GetElementNameFor<User>(u => u.Password).Should().Be("Password");
			Utils.GetElementNameFor<User>(u => u.PasswordAnswer).Should().Be("PasswordAnswer");
			Utils.GetElementNameFor<User, MembershipPasswordFormat>(u => u.PasswordFormat).Should().Be("PasswordFormat");
			Utils.GetElementNameFor<User>(u => u.PasswordQuestion).Should().Be("PasswordQuestion");
			Utils.GetElementNameFor<User, List<string>>(u => u.Roles).Should().Be("Roles");
			Utils.GetElementNameFor<User>(u => u.UserName).Should().Be("UserName");
		}

		[TestCase(@"User @#$@$@%@%@#^%^&%^*^&(^&() password 1234_345354.?.asdf'sfaf';34[053-5;as'", MembershipPasswordFormat.Clear, Result = @"User @#$@$@%@%@#^%^&%^*^&(^&() password 1234_345354.?.asdf'sfaf';34[053-5;as'")]
		[TestCase(@"User @#$@$@%@%@#^%^&%^*^&(^&() password 1234_345354.?.asdf'sfaf';34[053-5;as'", MembershipPasswordFormat.Hashed, Result = @"55007300650072002000400023002400400024004000250040002500400023005E0025005E00260025005E002A005E00260028005E002600280029002000700061007300730077006F0072006400200031003200330034005F003300340035003300350034002E003F002E0061007300640066002700730066006100660027003B00330034005B003000350033002D0035003B00610073002700AB85D1A6E941FFB3A1FFC66B4BAC0A683CEC72F8")]
		public string EncodeTest(string inputString, MembershipPasswordFormat passwordFormat)
		{
			return inputString.Encode(passwordFormat);
		}

		[TestCase(@"User @#$@$@%@%@#^%^&%^*^&(^&() password 1234_345354.?.asdf'sfaf';34[053-5;as'", MembershipPasswordFormat.Clear, Result = @"User @#$@$@%@%@#^%^&%^*^&(^&() password 1234_345354.?.asdf'sfaf';34[053-5;as'")]
		[TestCase(@"hash" , MembershipPasswordFormat.Hashed, ExpectedException = typeof(ArgumentException))]
		public string DecodeTest(string inputString, MembershipPasswordFormat passwordFormat)
		{
			return inputString.Decode(passwordFormat);
		}

		[TestCase(@"1234567890-=!@#$%^&*()_+qwertyuiop[]asdfghjkl;'\zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:|ZXCVBNM<>?")]
		public void EncodeDecodeEncryptTest(string input)
		{
			var encrypted = input.Encode(MembershipPasswordFormat.Encrypted);
			var dencrypted = encrypted.Decode(MembershipPasswordFormat.Encrypted);

			dencrypted.Should().Be(input);
		}
	}
}