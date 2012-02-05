using System.Web.Security;
using FluentAssertions;
using NUnit.Framework;

namespace Bikee.Security.Mongo.Tests
{
	[TestFixture]
	public class SecurityHelperTest
	{
		[TestCase(@"1234567890-=!@#$%^&*()_+qwertyuiop[]asdfghjkl;'\zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:|ZXCVBNM<>?")]
		public void EncodeDecodeUsingHashingTest(string inputString)
		{
			string salt;
			var hash1 = inputString.Encode(out salt, MembershipPasswordFormat.Hashed);
			hash1.Should().NotBe(inputString);

			var hash2 = inputString.Encode(out salt, MembershipPasswordFormat.Hashed);
			hash2.Should().NotBe(inputString);
			hash2.Should().NotBe(hash1);

			Assert.Throws<MembershipPasswordException>(() => hash1.Decode(MembershipPasswordFormat.Hashed));
		}

		[TestCase(@"1234567890-=!@#$%^&*()_+qwertyuiop[]asdfghjkl;'\zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:|ZXCVBNM<>?")]
		public void EncodeDecodeUsingEncryptionTest(string input)
		{
			var encrypted1 = input.Encode();
			encrypted1.Should().NotBe(input);

			var encrypted2 = input.Encode();
			encrypted2.Should().NotBe(input);
			encrypted2.Should().NotBe(encrypted1);

			var dencrypted1 = encrypted1.Decode();
			var dencrypted2 = encrypted2.Decode();
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

		[TestCase(@"1234567890-=!@#$%^&*()_+qwertyuiop[]asdfghjkl;'\zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:|ZXCVBNM<>?", MembershipPasswordFormat.Clear)]
		[TestCase(@"1234567890-=!@#$%^&*()_+qwertyuiop[]asdfghjkl;'\zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:|ZXCVBNM<>?", MembershipPasswordFormat.Encrypted)]
		[TestCase(@"1234567890-=!@#$%^&*()_+qwertyuiop[]asdfghjkl;'\zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:|ZXCVBNM<>?", MembershipPasswordFormat.Hashed)]
		public void VerifyPasswordTest(string password, MembershipPasswordFormat format)
		{
			string salt;
			var encoded = password.Encode(out salt, format);

			var result = password.VerifyPassword(encoded, format, salt);

			result.Should().BeTrue();
		}
	}
}