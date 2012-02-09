using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Linq;
using System.Web.Security;
using FluentMongo.Linq;
using MongoDB.Bson;
using MongoDB.Driver;
using MongoDB.Driver.Builders;

namespace Bikee.Security.Mongo
{
	public class MongoRoleProvider : RoleProvider
	{
		#region Consts

		private const int MaxUsernameLength = 100;
		private const int MaxRoleLength = 256;

		#endregion

		#region Fileds

		private MongoDatabase database;
		private string applicationName;
		private string userCollectionSuffix;
		private string roleCollectionSuffix;
		private string invalidUsernameCharacters;
		private string invalidRoleCharacters;
		private string connectionString;

		#endregion

		public string RoleCollectionName { get; protected set; }
		public string UserCollectionName { get; protected set; }

		protected MongoCollection<BsonDocument> RoleCollection { get; set; }
		protected MongoCollection<User> UserCollection { get; set; }

		#region Overrides of MongoRoleProvider

		/// <summary>
		/// Gets or sets the name of the application to store and retrieve role information for.
		/// </summary>
		/// <returns>
		/// The name of the application to store and retrieve role information for.
		/// </returns>
		public override string ApplicationName
		{
			get { return this.applicationName; }
			set
			{
				this.applicationName = value;
				this.UserCollectionName = MongoHelper.GenerateCollectionName(value, this.userCollectionSuffix);
				this.RoleCollectionName = MongoHelper.GenerateCollectionName(value, this.roleCollectionSuffix);
				this.UserCollection = this.database.GetCollection<User>(this.UserCollectionName);
				this.RoleCollection = this.database.GetCollection(this.RoleCollectionName);
			}
		}

		public override void Initialize(string name, NameValueCollection config)
		{
			if (config == null)
			{
				throw new ArgumentNullException("config");
			}

			if (string.IsNullOrEmpty(name))
			{
				name = this.GetType().Name;
			}

			if (string.IsNullOrEmpty(config["description"]))
			{
				config.Remove("description");
				config.Add("description", this.GetType().Name);
			}

			base.Initialize(name, config);

			this.invalidUsernameCharacters = SecurityHelper.GetConfigValue(config["invalidUsernameCharacters"], ",%\"/{}()''");
			this.invalidRoleCharacters = SecurityHelper.GetConfigValue(config["invalidRoleCharacters"], ",%");
			this.roleCollectionSuffix = SecurityHelper.GetConfigValue(config["roleCollectionSuffix"], "roles");
			this.userCollectionSuffix = SecurityHelper.GetConfigValue(config["userCollectionSuffix"], "users");
			this.applicationName = SecurityHelper.GetConfigValue(config["applicationName"], System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);

			var connectionStringSettings = ConfigurationManager.ConnectionStrings[config["connectionStringName"]];
			if (connectionStringSettings == null || string.IsNullOrEmpty(connectionStringSettings.ConnectionString.Trim()))
			{
				throw new ProviderException("Connection string cannot be blank.");
			}

			this.connectionString = connectionStringSettings.ConnectionString;

			this.InitDatabase();
			this.EnsureIndexes();
		}

		/// <summary>
		/// Gets a value indicating whether the specified user is in the specified role for the configured applicationName.
		/// </summary>
		/// <returns>
		/// true if the specified user is in the specified role for the configured applicationName; otherwise, false.
		/// </returns>
		/// <param name="username">The user name to search for.</param><param name="roleName">The role to search in.</param>
		public override bool IsUserInRole(string username, string roleName)
		{
			this.ValidateUserName(username);
			this.ValidateRoleName(roleName);

			return UserCollection.AsQueryable().Any(u => u.LowercaseUsername == username.ToLowerInvariant() &&
																										u.Roles.Contains(roleName.ToLowerInvariant()));
		}

		/// <summary>
		/// Gets a list of the roles that a specified user is in for the configured applicationName.
		/// </summary>
		/// <returns>
		/// A string array containing the names of all the roles that the specified user is in for the configured applicationName.
		/// </returns>
		/// <param name="username">The user to return a list of roles for.</param>
		public override string[] GetRolesForUser(string username)
		{
			this.ValidateUserName(username);

			return (from user in this.UserCollection.AsQueryable()
							where user.LowercaseUsername == username.ToLowerInvariant()
							select user.Roles.ToArray()).FirstOrDefault();
		}

		/// <summary>
		/// Adds a new role to the data source for the configured applicationName.
		/// </summary>
		/// <param name="roleName">The name of the role to create.</param>
		public override void CreateRole(string roleName)
		{
			this.ValidateRoleName(roleName);

			var doc = new BsonDocument();
			doc.SetDocumentId(roleName.ToLowerInvariant());

			var result = this.RoleCollection.Save(doc, SafeMode.True);
			if (!result.Ok)
			{
				throw new ProviderException(String.Format("Could not create role '{0}'. Reason: {1}", roleName, result.LastErrorMessage));
			}
		}

		/// <summary>
		/// Removes a role from the data source for the configured applicationName.
		/// </summary>
		/// <returns>
		/// true if the role was successfully deleted; otherwise, false.
		/// </returns>
		/// <param name="roleName">The name of the role to delete.</param><param name="throwOnPopulatedRole">If true, throw an exception if <paramref name="roleName"/> has one or more members and do not delete <paramref name="roleName"/>.</param>
		public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
		{
			this.ValidateRoleName(roleName);

			var rolePopulated = this.UserCollection.AsQueryable().Any(u => u.Roles.Contains(roleName.ToLowerInvariant()));
			if (throwOnPopulatedRole && rolePopulated)
			{
				throw new ProviderException("Role is not empty.");
			}

			var result = RoleCollection.Remove(Query.EQ("_id", roleName.ToLowerInvariant()), SafeMode.True);
			return result.Ok;
		}

		/// <summary>
		/// Gets a value indicating whether the specified role name already exists in the role data source for the configured applicationName.
		/// </summary>
		/// <returns>
		/// true if the role name already exists in the data source for the configured applicationName; otherwise, false.
		/// </returns>
		/// <param name="roleName">The name of the role to search for in the data source.</param>
		public override bool RoleExists(string roleName)
		{
			this.ValidateRoleName(roleName);
			return this.RoleCollection.FindOneById(BsonValue.Create(roleName.ToLowerInvariant())) != null;
		}

		/// <summary>
		/// Adds the specified user names to the specified roles for the configured applicationName.
		/// </summary>
		/// <param name="usernames">A string array of user names to be added to the specified roles. </param><param name="roleNames">A string array of the role names to add the specified user names to.</param>
		public override void AddUsersToRoles(string[] usernames, string[] roleNames)
		{
			if (usernames == null)
			{
				throw new ArgumentNullException("usernames");
			}

			if (!usernames.Any())
			{
				throw new ArgumentException("usernames is empty.");
			}

			if (roleNames == null)
			{
				throw new ArgumentNullException("usernames");
			}

			if (!roleNames.Any())
			{
				throw new ArgumentException("roleNames is empty.");
			}

			// ensure lowercase
			var roles = roleNames.Select(role =>
			{
				this.ValidateRoleName(role);
				return role.ToLowerInvariant();
			}).ToList();
			var users = usernames.Select(username =>
			{
				this.ValidateRoleName(username);
				return username.ToLowerInvariant();
			}).ToList();

			// first add any non-existant roles to roles collection
			// a) pull all roles, filter out existing, push new
			//    ...or 
			// b) save all passed in roles 

			foreach (var role in roles)
			{
				this.CreateRole(role);
			}

			// now update all users' roles
			var query = Query.In(MongoHelper.GetElementNameFor<User>(u => u.LowercaseUsername), new BsonArray(users.ToArray()));
			var update = Update.AddToSetEachWrapped<string>(MongoHelper.GetElementNameFor<User>(u => u.Roles), roles);

			var result = UserCollection.Update(query, update, UpdateFlags.Multi, SafeMode.True);

			if (!result.Ok)
			{
				throw new ProviderException(result.LastErrorMessage);
			}
		}

		/// <summary>
		/// Removes the specified user names from the specified roles for the configured applicationName.
		/// </summary>
		/// <param name="usernames">A string array of user names to be removed from the specified roles. </param><param name="roleNames">A string array of role names to remove the specified user names from.</param>
		public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
		{
			if (usernames == null)
			{
				throw new ArgumentNullException("usernames");
			}

			if (!usernames.Any())
			{
				throw new ArgumentException("usernames is empty.");
			}

			if (roleNames == null)
			{
				throw new ArgumentNullException("usernames");
			}

			if (!roleNames.Any())
			{
				throw new ArgumentException("roleNames is empty.");
			}

			// ensure lowercase
			var roles = roleNames.Select(role =>
			{
				this.ValidateRoleName(role);
				return role.ToLowerInvariant();
			}).ToList();
			var users = usernames.Select(username =>
			{
				this.ValidateRoleName(username);
				return username.ToLowerInvariant();
			}).ToList();

			var query = Query.In(MongoHelper.GetElementNameFor<User>(u => u.LowercaseUsername), new BsonArray(users.ToArray()));
			var update = Update.PullAllWrapped<string>(MongoHelper.GetElementNameFor<User>(u => u.Roles), roles);

			var result = this.UserCollection.Update(query, update, UpdateFlags.Multi, SafeMode.True);
			if (!result.Ok)
			{
				throw new ProviderException(result.LastErrorMessage);
			}
		}

		/// <summary>
		/// Gets a list of users in the specified role for the configured applicationName.
		/// </summary>
		/// <returns>
		/// A string array containing the names of all the users who are members of the specified role for the configured applicationName.
		/// </returns>
		/// <param name="roleName">The name of the role to get the list of users for.</param>
		public override string[] GetUsersInRole(string roleName)
		{
			this.ValidateRoleName(roleName);

			return (from user in this.UserCollection.AsQueryable()
							where user.Roles.Contains(roleName.ToLowerInvariant())
							select user.UserName).ToArray();
		}

		/// <summary>
		/// Gets a list of all the roles for the configured applicationName.
		/// </summary>
		/// <returns>
		/// A string array containing the names of all the roles stored in the data source for the configured applicationName.
		/// </returns>
		public override string[] GetAllRoles()
		{
			return this.RoleCollection.FindAll().Select(d => d["_id"].AsString).ToArray();
		}

		/// <summary>
		/// Gets an array of user names in a role where the user name contains the specified user name to match.
		/// </summary>
		/// <returns>
		/// A string array containing the names of all the users where the user name matches <paramref name="usernameToMatch"/> and the user is a member of the specified role.
		/// </returns>
		/// <param name="roleName">The role to search in.</param><param name="usernameToMatch">The user name to search for.</param>
		public override string[] FindUsersInRole(string roleName, string usernameToMatch)
		{
			this.ValidateRoleName(roleName);

			if (string.IsNullOrWhiteSpace(usernameToMatch))
			{
				return new string[0];
			}

			var userNameField = MongoHelper.GetElementNameFor<User>(u => u.LowercaseUsername);
			var roleField = MongoHelper.GetElementNameFor<User>(u => u.Roles);

			var nameMatchQuery = Query.Matches(userNameField, new BsonRegularExpression(usernameToMatch));
			var roleMatchQuery = Query.EQ(roleField, roleName.ToLowerInvariant());
			var query = Query.And(nameMatchQuery, roleMatchQuery);

			var cursor = UserCollection.FindAs<BsonDocument>(query);

			// only want the usernames
			cursor.SetFields(Fields.Include(userNameField).Exclude("_id"));
			return cursor.Select(doc => doc[userNameField].AsString).ToArray();
		}

		#endregion

		protected virtual void InitDatabase()
		{
			this.database = MongoDatabase.Create(this.connectionString);

			// This will init collections.
			this.ApplicationName = this.applicationName;
		}

		protected virtual void EnsureIndexes()
		{
			this.UserCollection.EnsureIndex(MongoHelper.GetElementNameFor<User>(u => u.LowercaseUsername));
			this.UserCollection.EnsureIndex(MongoHelper.GetElementNameFor<User>(u => u.Roles));
		}

		protected virtual void ValidateRoleName(string roleName)
		{
			if (roleName == null)
			{
				throw new ArgumentNullException("roleName");
			}

			if (roleName.Trim() == string.Empty)
			{
				throw new ArgumentException("Role cannot be blank.");
			}

			if (roleName.Length > MaxRoleLength)
			{
				throw new ArgumentException("Role name is too long.");
			}

			if (this.invalidRoleCharacters.Any(roleName.Contains))
			{
				throw new ArgumentException("Role name contains invalid character(s).");
			}
		}

		protected virtual void ValidateUserName(string userName)
		{
			if (userName == null)
			{
				throw new ArgumentNullException("userName");
			}

			if (userName.Trim() == string.Empty)
			{
				throw new ArgumentException("User name cannot be blank.");
			}

			if (userName.Length > MaxUsernameLength)
			{
				throw new ArgumentException("User name name is too long.");
			}

			if (this.invalidUsernameCharacters.Any(userName.Contains))
			{
				throw new ArgumentException("User name contains invalid character(s).");
			}
		}
	}
}