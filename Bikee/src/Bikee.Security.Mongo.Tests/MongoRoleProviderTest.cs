using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Linq;
using System.Web.Security;
using Bikee.Mongo.Tests;
using FluentAssertions;
using NUnit.Framework;

namespace Bikee.Security.Mongo.Tests
{
	[TestFixture]
	public class MongoRoleProviderTest : MongoTestBase
	{
		[Test]
		public void CreateAndDeleteRolesTest()
		{
			// Add the role
			Roles.CreateRole("Administrator");
			string[] roles = Roles.GetAllRoles();
			Assert.AreEqual(1, roles.Length);
			Assert.AreEqual("administrator", roles[0]);

			// now delete the role
			Roles.DeleteRole("Administrator", false);
			roles = Roles.GetAllRoles();
			Assert.AreEqual(0, roles.Length);
		}

		[Test]
		public void AddUsersToRoles()
		{
			Membership.CreateUser("eve", "barbar1!", "eve@q.com");
			Membership.CreateUser("eve2", "barbar1!", "eve2@q.com");
			Membership.CreateUser("eve3", "barbar1!", "eve3@q.com");
			Roles.CreateRole("Administrator");
			Roles.CreateRole("User");
			Roles.CreateRole("Editor");
			Roles.AddUsersToRoles(new[] { "eve", "eve2" }, new[] { "Administrator", "User" });
			Assert.IsTrue(Roles.IsUserInRole("eve", "Administrator"));
			Assert.IsTrue(Roles.IsUserInRole("eve", "User"));
			Assert.IsFalse(Roles.IsUserInRole("eve", "Editor"));
			Assert.IsTrue(Roles.IsUserInRole("eve2", "Administrator"));
			Assert.IsTrue(Roles.IsUserInRole("eve2", "User"));
			Assert.IsFalse(Roles.IsUserInRole("eve2", "Editor"));

			Roles.AddUsersToRoles(new[] { "eve3" }, new[] { "Editor", "User" });
			Assert.IsFalse(Roles.IsUserInRole("eve3", "Administrator"));
			Assert.IsTrue(Roles.IsUserInRole("eve3", "User"));
			Assert.IsTrue(Roles.IsUserInRole("eve3", "Editor"));
		}

		[Test]
		public void RemoveUsersFromRoleTest()
		{
			Membership.CreateUser("eve", "barbar1!", "eve@q.com");
			Membership.CreateUser("eve2", "barbar1!", "eve2@q.com");
			Membership.CreateUser("eve3", "barbar1!", "eve3@q.com");
			Roles.CreateRole("Administrator");
			Roles.CreateRole("User");
			Roles.CreateRole("Editor");

			// test with one user
			Roles.AddUsersToRoles(new[] { "eve" }, new[] { "Editor", "User" });
			Assert.AreEqual(2, Roles.GetRolesForUser("eve").Length);
			Assert.IsTrue(Roles.IsUserInRole("eve", "Editor"));
			Assert.IsTrue(Roles.IsUserInRole("eve", "User"));

			// remove User role
			Roles.RemoveUsersFromRoles(new[] { "eve" }, new[] { "User" });
			Assert.IsFalse(Roles.IsUserInRole("eve", "User"));
			Assert.IsTrue(Roles.IsUserInRole("eve", "Editor"));
			Assert.AreEqual(1, Roles.GetRolesForUser("eve").Length);

			// try remove again
			Roles.RemoveUsersFromRoles(new[] { "eve" }, new[] { "User" });
			Assert.IsFalse(Roles.IsUserInRole("eve", "User"));

			// test with two users
			Assert.IsFalse(Roles.IsUserInRole("eve2", "Administrator"));
			Roles.AddUsersToRoles(new[] { "eve2", "eve3" }, new[] { "Administrator", "User" });
			Assert.IsTrue(Roles.IsUserInRole("eve2", "Administrator"));
			Assert.IsTrue(Roles.IsUserInRole("eve3", "Administrator"));

			// remove admin role
			Roles.RemoveUsersFromRoles(new[] { "eve2" }, new[] { "Administrator" });
			Assert.IsFalse(Roles.IsUserInRole("eve2", "Administrator"));
			Assert.IsTrue(Roles.IsUserInRole("eve2", "User"));
			Assert.AreEqual(1, Roles.GetRolesForUser("eve2").Length);
			Assert.AreEqual("user", Roles.GetRolesForUser("eve2")[0]);

			// verify didn't touch other user
			Assert.IsTrue(Roles.IsUserInRole("eve3", "Administrator"));

			// try remove again
			Roles.RemoveUsersFromRoles(new[] { "eve2" }, new[] { "Administrator" });
			Assert.IsFalse(Roles.IsUserInRole("eve2", "Administrator"));
		}

		[Test]
		public void AddNonExistingUserToRoleTest()
		{
			Roles.CreateRole("Administrator");
			Roles.AddUsersToRoles(new[] { "eve" }, new[] { "Administrator" });

			Assert.IsFalse(Roles.IsUserInRole("eve", "Administrator"));
		}

		[TestCase("test", null, ExpectedException = typeof(ArgumentNullException))]
		[TestCase("test", "", ExpectedException = typeof(ArgumentException))]
		public void InvalidRoleTest(string userName, string roleName)
		{
			Roles.AddUsersToRoles(new[] { userName }, new[] { roleName });
		}

		[TestCase(null, "admin", ExpectedException = typeof(ArgumentNullException))]
		[TestCase("", "admin", ExpectedException = typeof(ArgumentException))]
		public void InvalidUserNameTest(string userName, string roleName)
		{
			Roles.CreateRole("Administrator");
			Roles.AddUsersToRoles(new[] { userName }, new[] { roleName });
		}

		[Test]
		public void AddUserToRoleWithRoleClassTest()
		{
			Roles.CreateRole("Administrator");
			Membership.CreateUser("eve", "bar@eve", "eve@boo.com");

			Roles.AddUserToRole("eve", "Administrator");
			Assert.IsTrue(Roles.IsUserInRole("eve", "Administrator"));
		}

		[Test]
		public void GetRolesForUserTest()
		{
			Membership.CreateUser("eve", "bar@eve", "eve@boo.com");
			Roles.CreateRole("Administrator");
			Roles.CreateRole("User");
			Roles.CreateRole("Editor");

			Roles.AddUsersToRoles(new[] { "eve" }, new[] { "Editor", "User", "Administrator" });
			Assert.AreEqual(3, Roles.GetRolesForUser("eve").Length);
			Assert.IsTrue(Roles.IsUserInRole("eve", "Editor"));
			Assert.IsTrue(Roles.IsUserInRole("eve", "User"));
			Assert.IsTrue(Roles.IsUserInRole("eve", "Administrator"));
		}

		[Test]
		public void GetAllRolesTest()
		{
			Roles.CreateRole("Administrator");
			Roles.CreateRole("User");
			Roles.CreateRole("Editor");

			var roles = Roles.GetAllRoles();

			Assert.AreEqual(3, roles.Length);
			Assert.IsTrue(roles.Contains("administrator"));
			Assert.IsTrue(roles.Contains("user"));
			Assert.IsTrue(roles.Contains("editor"));
		}

		[Test]
		public void RoleExistsTest()
		{
			Roles.CreateRole("Administrator");
			Roles.CreateRole("User");
			Roles.CreateRole("Editor");

			Assert.IsTrue(Roles.RoleExists("Administrator"));
			Assert.IsTrue(Roles.RoleExists("User"));
			Assert.IsTrue(Roles.RoleExists("Editor"));
			Assert.IsFalse(Roles.RoleExists("Jack"));
		}

		[Test]
		public void CheckIsUserInRoleForNonExistantUser()
		{
			var actual = Roles.IsUserInRole("not-there", "admin");
			Assert.AreEqual(false, actual);
		}

		[Test]
		public void IsUserInRoleCrossDomain()
		{
			Membership.CreateUser("foo", "bar!bar", "foo@bar.com");

			var mongoMembershipProvider = new MongoMembershipProvider();
			var mongoMembershipProviderConfig = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"applicationName", "app2"},
			};
			mongoMembershipProvider.Initialize("MongoMembershipProvider", mongoMembershipProviderConfig);

			var roleProvider = new MongoRoleProvider();
			var roleProviderConfig = new NameValueCollection
			{
				{"connectionStringName", ConfigurationManager.ConnectionStrings[0].Name},
				{"applicationName", "app2"}
			};
			roleProvider.Initialize("MongoRoleProvider", roleProviderConfig);

			roleProvider.CreateRole("Administrator");
			roleProvider.AddUsersToRoles(new[] { "foo" }, new[] { "Administrator" });

			Assert.IsFalse(roleProvider.IsUserInRole("foo", "Administrator"));
		}

		[Test]
		public void QueryArrayTest()
		{
			Membership.CreateUser("eve", "bar@eve", "eve@boo.com");
			Membership.CreateUser("evelyn", "bar@evelyn", "evelyn@boo.com");
			Membership.CreateUser("emily", "bar@emily", "emily@boo.com");
			Membership.CreateUser("robert", "bar@robert", "robert@boo.com");
			Membership.CreateUser("carly", "bar@carly", "carly@boo.com");

			Roles.CreateRole("User");
			Roles.CreateRole("Editor");

			Roles.AddUsersToRoles(new[] { "eve", "evelyn", "emily", "robert", "carly" }, new[] { "User" });
			Roles.AddUsersToRoles(new[] { "emily", "robert", "carly" }, new[] { "Editor" });

			var provider = (MongoRoleProvider)Roles.Provider;

			var users = this.MongoDatabase.GetCollection<User>(provider.UserCollectionName).FindAll();
			users.Count(u => u.Roles.Contains("editor")).Should().Be(3);
		}

		[Test]
		public void FindUsersInRoleTest()
		{
			Membership.CreateUser("eve", "bar@eve", "eve@boo.com");
			Membership.CreateUser("evelyn", "bar@evelyn", "evelyn@boo.com");
			Membership.CreateUser("emily", "bar@emily", "emily@boo.com");
			Membership.CreateUser("robert", "bar@robert", "robert@boo.com");
			Membership.CreateUser("carly", "bar@carly", "carly@boo.com");
			Roles.CreateRole("User");

			Roles.AddUsersToRoles(new[] { "eve", "evelyn", "emily", "robert", "carly" }, new[] { "User" });

			// no % (startsWith)
			var users = Roles.FindUsersInRole("User", "eve");
			Assert.AreEqual(2, users.Length);
			Assert.IsTrue(users.Contains("eve"));
			Assert.IsTrue(users.Contains("evelyn"));

			users = Roles.FindUsersInRole("User", "bob");
			Assert.AreEqual(0, users.Length);

			users = Roles.FindUsersInRole("User", "*obert");
			Assert.AreEqual(0, users.Length);

			// StartsWith
			users = Roles.FindUsersInRole("User", "eve*");
			Assert.AreEqual(2, users.Length);
			Assert.IsTrue(users.Contains("eve"));
			Assert.IsTrue(users.Contains("evelyn"));

			users = Roles.FindUsersInRole("User", "bob");
			Assert.AreEqual(0, users.Length);

			// EndsWith
			users = Roles.FindUsersInRole("User", "ly$");
			Assert.AreEqual(2, users.Length);
			Assert.IsTrue(users.Contains("emily"));
			Assert.IsTrue(users.Contains("carly"));

			users = Roles.FindUsersInRole("User", "*ark");
			Assert.AreEqual(0, users.Length);

			// Contains
			users = Roles.FindUsersInRole("User", "^.*ly.*$");
			Assert.AreEqual(3, users.Length);
			Assert.IsTrue(users.Contains("evelyn"));
			Assert.IsTrue(users.Contains("emily"));
			Assert.IsTrue(users.Contains("carly"));

			users = Roles.FindUsersInRole("User", "%bob%");
			Assert.AreEqual(0, users.Length);
		}

		[Test]
		public void GetUsersInRoleTest()
		{
			Membership.CreateUser("eve", "bar@eve", "eve@boo.com");
			Membership.CreateUser("evelyn", "bar@evelyn", "evelyn@boo.com");
			Membership.CreateUser("emily", "bar@emily", "emily@boo.com");
			Membership.CreateUser("robert", "bar@robert", "robert@boo.com");
			Roles.CreateRole("Administrator");
			Roles.CreateRole("User");
			Roles.CreateRole("Editor");

			Roles.AddUsersToRoles(new[] { "eve", "evelyn", "emily", "robert" }, new[] { "User" });
			Roles.AddUsersToRoles(new[] { "eve", "evelyn" }, new[] { "Editor" });
			Roles.AddUsersToRoles(new[] { "eve" }, new[] { "Administrator" });

			var users = Roles.GetUsersInRole("User");
			var editors = Roles.GetUsersInRole("Editor");
			var admins = Roles.GetUsersInRole("Administrator");

			Assert.AreEqual(4, users.Length);
			Assert.IsTrue(users.Contains("eve"));
			Assert.IsTrue(users.Contains("evelyn"));
			Assert.IsTrue(users.Contains("emily"));
			Assert.IsTrue(users.Contains("robert"));

			Assert.AreEqual(2, editors.Length);
			Assert.IsTrue(editors.Contains("eve"));
			Assert.IsTrue(editors.Contains("evelyn"));
			Assert.IsFalse(editors.Contains("emily"));
			Assert.IsFalse(editors.Contains("robert"));

			Assert.AreEqual(1, admins.Length);
			Assert.IsTrue(admins.Contains("eve"));
			Assert.IsFalse(admins.Contains("evelyn"));
			Assert.IsFalse(admins.Contains("emily"));
			Assert.IsFalse(admins.Contains("robert"));
		}
	}
}