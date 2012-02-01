using System;
using System.Collections.Generic;
using System.Security;
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

		[TestCase(@"1234567890-=!@#$%^&*()_+qwertyuiop[]asdfghjkl;'\zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:|ZXCVBNM<>?")]
		public void EncodeDecodeUsingHashingTest(string inputString)
		{
			var hash1 = inputString.Encode(MembershipPasswordFormat.Hashed);
			hash1.Should().NotBe(inputString);

			var hash2 = inputString.Encode(MembershipPasswordFormat.Hashed);
			hash2.Should().NotBe(inputString);
			hash2.Should().NotBe(hash1);

			Assert.Throws<SecurityException>(() => hash1.Decode(MembershipPasswordFormat.Hashed));
		}

		[TestCase(@"1234567890-=!@#$%^&*()_+qwertyuiop[]asdfghjkl;'\zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:|ZXCVBNM<>?")]
		public void EncodeDecodeUsingEncryptionTest(string input)
		{
			var encrypted1 = input.Encode(MembershipPasswordFormat.Encrypted);
			encrypted1.Should().NotBe(input);

			var encrypted2 = input.Encode(MembershipPasswordFormat.Encrypted);
			encrypted2.Should().NotBe(input);
			encrypted2.Should().NotBe(encrypted1);

			var dencrypted1 = encrypted1.Decode(MembershipPasswordFormat.Encrypted);
			var dencrypted2 = encrypted2.Decode(MembershipPasswordFormat.Encrypted);
			dencrypted1.Should().Be(dencrypted2);
		}

		[TestCase(@"1234567890-=!@#$%^&*()_+qwertyuiop[]asdfghjkl;'\zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:|ZXCVBNM<>?")]
		public void EncodeDecodeUsingNothingTest(string input)
		{
			var encrypted = input.Encode(MembershipPasswordFormat.Clear);
			encrypted.Should().Be(input);

			var dencrypted = encrypted.Decode(MembershipPasswordFormat.Clear);
			dencrypted.Should().Be(input);
		}
	}
}