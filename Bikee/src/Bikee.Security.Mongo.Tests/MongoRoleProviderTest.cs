using System.Collections.Specialized;
using System.Web.Security;
using Bikee.Mongo.Tests;
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
			Roles.AddUsersToRoles(new [] { "eve", "eve2" }, new [] { "Administrator", "User" });
			Assert.IsTrue(Roles.IsUserInRole("eve", "Administrator"));
			Assert.IsTrue(Roles.IsUserInRole("eve", "User"));
			Assert.IsFalse(Roles.IsUserInRole("eve", "Editor"));
			Assert.IsTrue(Roles.IsUserInRole("eve2", "Administrator"));
			Assert.IsTrue(Roles.IsUserInRole("eve2", "User"));
			Assert.IsFalse(Roles.IsUserInRole("eve2", "Editor"));

			Roles.AddUsersToRoles(new [] { "eve3" },new [] { "Editor", "User" });
			Assert.IsFalse(Roles.IsUserInRole("eve3", "Administrator"));
			Assert.IsTrue(Roles.IsUserInRole("eve3", "User"));
			Assert.IsTrue(Roles.IsUserInRole("eve3", "Editor"));
		}
	}
}