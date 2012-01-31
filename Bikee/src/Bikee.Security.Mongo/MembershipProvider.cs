using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web.Configuration;
using System.Web.Security;
using Bikee.Security.Domain;
using FluentMongo.Linq;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Options;
using MongoDB.Driver;
using MongoDB.Driver.Builders;

namespace Bikee.Security.Mongo
{
	// How to: Sample Membership Provider Implementation :
	// http://msdn.microsoft.com/en-us/library/ie/6tc47t75.aspx
	public class MembershipProvider : System.Web.Security.MembershipProvider
	{
		private string applicationName;
		private string connectionString;
		private int maxInvalidPasswordAttempts;
		private int passwordAttemptWindow;
		private int minRequiredNonAlphanumericCharacters;
		private int minRequiredPasswordLength;
		private string passwordStrengthRegularExpression;
		private bool enablePasswordReset;
		private bool enablePasswordRetrieval;
		private bool requiresQuestionAndAnswer;
		private bool requiresUniqueEmail;
		private string usersCollectionName;
		private MembershipPasswordFormat passwordFormat;
		private MachineKeySection machineKey;

		private const string EventLog = "Application";
		private const string EventSource = "MongoMembershipProvider";
		private const int NewPasswordLength = 8;
		private const int MaxUsernameLength = 256;
		private const int MaxPasswordLength = 128;
		private const int MaxPasswordAnswerLength = 128;
		private const int MaxEmailLength = 256;
		private const int MaxPasswordQuestionLength = 256;

		#region Custom  Properties

		public bool WriteExceptionsToEventLog { get; set; }
		protected string InvalidUsernameCharacters { get; set; }
		protected string InvalidEmailCharacters { get; set; }
		public string CollectionName { get; set; }
		public MongoCollection<User> UsersCollection { get; set; }
		public MongoDatabase Database { get; set; }

		#endregion

		#region Overrides of MembershipProvider Methods

		/// <summary>
		/// Initializes the provider.
		/// </summary>
		/// <param name="name">The friendly name of the provider.</param>
		/// <param name="config">A collection of the name/value pairs representing the provider-specific attributes specified in the configuration for this provider.</param>
		/// <exception cref="T:System.ArgumentNullException">The name of the provider is null.</exception>
		///   
		/// <exception cref="T:System.ArgumentException">The name of the provider has a length of zero.</exception>
		///   
		/// <exception cref="T:System.InvalidOperationException">An attempt is made to call <see cref="M:System.Configuration.Provider.ProviderBase.Initialize(System.String,System.Collections.Specialized.NameValueCollection)"/> on a provider after the provider has already been initialized.</exception>
		public override void Initialize(string name, NameValueCollection config)
		{
			if (string.IsNullOrEmpty(name))
			{
				name = "MongoMembershipProvider";
			}

			if (string.IsNullOrEmpty(config["description"]))
			{
				config.Remove("description");
				config.Add("description", "MongoDB Membership provider");
			}

			base.Initialize(name, config);

			this.applicationName = Utils.GetConfigValue(config["applicationName"], System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
			this.maxInvalidPasswordAttempts = Utils.GetConfigValue(config["maxInvalidPasswordAttempts"], 5);
			this.passwordAttemptWindow = Utils.GetConfigValue(config["passwordAttemptWindow"], 10);
			this.minRequiredNonAlphanumericCharacters = Utils.GetConfigValue(config["minRequiredNonAlphanumericCharacters"], 1);
			this.minRequiredPasswordLength = Utils.GetConfigValue(config["minRequiredPasswordLength"], 7);
			this.passwordStrengthRegularExpression = Utils.GetConfigValue(config["passwordStrengthRegularExpression"], "");
			this.enablePasswordReset = Utils.GetConfigValue(config["enablePasswordReset"], true);
			this.enablePasswordRetrieval = Utils.GetConfigValue(config["enablePasswordRetrieval"], false);
			this.requiresQuestionAndAnswer = Utils.GetConfigValue(config["requiresQuestionAndAnswer"], false);
			this.requiresUniqueEmail = Utils.GetConfigValue(config["requiresUniqueEmail"], true);

			this.usersCollectionName = Utils.GetConfigValue(config["usersCollectionName"], "users");

			this.InvalidUsernameCharacters = Utils.GetConfigValue(config["invalidUsernameCharacters"], ",%");
			this.InvalidEmailCharacters = Utils.GetConfigValue(config["invalidEmailCharacters"], ",%");
			this.WriteExceptionsToEventLog = Utils.GetConfigValue(config["writeExceptionsToEventLog"], true);

			string passwordFormatConfig = config["passwordFormat"] ?? "Hashed";
			switch (passwordFormatConfig)
			{
				case "Hashed":
					this.passwordFormat = MembershipPasswordFormat.Hashed;
					break;
				case "Encrypted":
					this.passwordFormat = MembershipPasswordFormat.Encrypted;
					break;
				case "Clear":
					this.passwordFormat = MembershipPasswordFormat.Clear;
					break;
				default:
					this.HandleExceptionAndThrow(new MongoProviderException("Password format not supported."));
					break;
			}

			if ((this.passwordFormat == MembershipPasswordFormat.Hashed) && EnablePasswordRetrieval)
			{
				this.HandleExceptionAndThrow(new MongoProviderException("Configured settings are invalid: Hashed passwords cannot be retrieved. Either set the password format to different type, or set supportsPasswordRetrieval to false."));
			}

			var connectionStringSettings = ConfigurationManager.ConnectionStrings[config["connectionStringName"]];
			if (connectionStringSettings == null || string.IsNullOrEmpty(connectionStringSettings.ConnectionString.Trim()))
			{
				this.HandleExceptionAndThrow(new MongoProviderException("Connection string cannot be blank."));
			}

			this.connectionString = connectionStringSettings.ConnectionString;

			// Get encryption and decryption key information from the configuration.
			this.machineKey = (MachineKeySection)ConfigurationManager.GetSection("system.web/machineKey");
			//var webConfig = WebConfigurationManager.OpenWebConfiguration(System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
			//this.machineKey = (MachineKeySection)webConfig.GetSection("system.web/machineKey");

			if (this.machineKey == null)
			{
				this.HandleExceptionAndThrow(new MongoProviderException("Machine key is not set"));
			}

			if (this.machineKey.ValidationKey.Contains("AutoGenerate") && this.PasswordFormat != MembershipPasswordFormat.Clear)
			{
				this.HandleExceptionAndThrow(new MongoProviderException("Hashed or Encrypted passwords are not supported with auto-generated keys."));
			}

			this.RegigisterMaps();
			this.InitMongoDB();
		}

		/// <summary>
		/// Adds a new membership user to the data source.
		/// </summary>
		/// <returns>
		/// A <see cref="T:System.Web.Security.MembershipUser"/> object populated with the information for the newly created user.
		/// </returns>
		/// <param name="username">The user name for the new user. </param><param name="password">The password for the new user. </param><param name="email">The e-email address for the new user.</param><param name="passwordQuestion">The password question for the new user.</param><param name="passwordAnswer">The password answer for the new user</param><param name="isApproved">Whether or not the new user is approved to be validated.</param><param name="providerUserKey">The unique identifier from the membership data source for the user.</param><param name="status">A <see cref="T:System.Web.Security.MembershipCreateStatus"/> enumeration value indicating whether the user was created successfully.</param>
		public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
		{
			if (string.IsNullOrEmpty(username) || this.InvalidUsernameCharacters.Any(username.Contains) || username.Length > MaxUsernameLength)
			{
				status = MembershipCreateStatus.InvalidUserName;
				return null;
			}
			username = username.Trim();

			if (string.IsNullOrEmpty(email) || this.InvalidEmailCharacters.Any(email.Contains) || email.Length > MaxEmailLength)
			{
				status = MembershipCreateStatus.InvalidEmail;
				return null;
			}
			email = email.Trim();

			if (string.IsNullOrEmpty(password) || password.Length > MaxPasswordLength || password.Length < this.MinRequiredPasswordLength)
			{
				status = MembershipCreateStatus.InvalidPassword;
				return null;
			}

			if (!string.IsNullOrEmpty(this.PasswordStrengthRegularExpression) && !Regex.IsMatch(password, this.PasswordStrengthRegularExpression))
			{
				status = MembershipCreateStatus.InvalidPassword;
				return null;
			}

			if (this.MinRequiredNonAlphanumericCharacters > 0)
			{
				int numNonAlphaNumericChars = password.Where((t, i) => !char.IsLetterOrDigit(password, i)).Count();

				if (numNonAlphaNumericChars < this.MinRequiredNonAlphanumericCharacters)
				{
					status = MembershipCreateStatus.InvalidPassword;
					return null;
				}
			}

			if ((string.IsNullOrEmpty(passwordQuestion) && this.RequiresQuestionAndAnswer) || ((passwordQuestion != null && passwordQuestion.Length > MaxPasswordQuestionLength)))
			{
				status = MembershipCreateStatus.InvalidQuestion;
				return null;
			}

			if ((string.IsNullOrEmpty(passwordAnswer) && this.RequiresQuestionAndAnswer) || ((passwordAnswer != null && passwordAnswer.Length > MaxPasswordAnswerLength)))
			{
				status = MembershipCreateStatus.InvalidAnswer;
				return null;
			}

			var args = new ValidatePasswordEventArgs(username, password, true);
			this.OnValidatingPassword(args);

			if (args.Cancel)
			{
				status = MembershipCreateStatus.InvalidPassword;
				return null;
			}

			if (this.RequiresUniqueEmail && !string.IsNullOrEmpty(this.GetUserNameByEmail(email)))
			{
				status = MembershipCreateStatus.DuplicateEmail;
				return null;
			}

			if (providerUserKey == null)
			{
				providerUserKey = ObjectId.GenerateNewId();
			}
			else if (!(providerUserKey is BsonValue))
			{
				status = MembershipCreateStatus.InvalidProviderUserKey;
				return null;
			}

			var membershipUser = this.GetUser(providerUserKey, false);
			if (membershipUser != null)
			{
				status = MembershipCreateStatus.DuplicateUserName;
				return null;
			}

			DateTime createDate = DateTime.UtcNow;

			var user = new User
			{
				Id = providerUserKey,
				UserName = username,
				LowercaseUsername = username.ToLowerInvariant(),
				DisplayName = username,
				Email = email,
				LowercaseEmail = email.ToLowerInvariant(),
				Password = password.Encode(this.PasswordFormat),
				PasswordQuestion = passwordQuestion,
				PasswordAnswer = passwordAnswer.Encode(this.PasswordFormat),
				PasswordFormat = MembershipPasswordFormat.Clear,
				IsApproved = isApproved,
				LastPasswordChangedDate = DateTime.MinValue,
				CreationDate = createDate,
				IsLockedOut = false,
				LastLockoutDate = DateTime.MinValue,
				LastLoginDate = DateTime.MinValue,
				LastActivityDate = createDate,
				FailedPasswordAnswerAttemptCount = 0,
				FailedPasswordAnswerAttemptWindowStart = DateTime.MinValue,
				FailedPasswordAttemptCount = 0,
				FailedPasswordAttemptWindowStart = DateTime.MinValue
			};

			this.SaveUser(user);

			status = MembershipCreateStatus.Success;
			return this.GetUser(providerUserKey, false);
		}

		/// <summary>
		/// Processes a request to update the password question and answer for a membership user.
		/// </summary>
		/// <returns>
		/// true if the password question and answer are updated successfully; otherwise, false.
		/// </returns>
		/// <param name="username">The user to change the password question and answer for. </param><param name="password">The password for the specified user. </param><param name="newPasswordQuestion">The new password question for the specified user. </param><param name="newPasswordAnswer">The new password answer for the specified user. </param>
		public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
		{
			if (string.IsNullOrEmpty(username) || this.InvalidUsernameCharacters.Any(username.Contains) || username.Length > MaxUsernameLength)
			{
				return false;
			}

			if (string.IsNullOrEmpty(password) || password.Length > MaxPasswordLength || password.Length < this.MinRequiredPasswordLength)
			{
				return false;
			}

			var user = this.GetUserByName(username);
			if (!this.ValidateUserPassword(user, password))
			{
				return false;
			}

			if ((string.IsNullOrEmpty(newPasswordQuestion) && this.RequiresQuestionAndAnswer) || ((newPasswordQuestion != null && newPasswordQuestion.Length > MaxPasswordQuestionLength)))
			{
				return false;
			}

			if ((string.IsNullOrEmpty(newPasswordAnswer) && this.RequiresQuestionAndAnswer) || ((newPasswordAnswer != null && newPasswordAnswer.Length > MaxPasswordAnswerLength)))
			{
				return false;
			}

			user.PasswordQuestion = newPasswordQuestion;
			user.PasswordAnswer = string.IsNullOrEmpty(newPasswordAnswer) ? null : newPasswordAnswer.Encode(user.PasswordFormat);

			return false;
		}

		/// <summary>
		/// Gets the password for the specified user name from the data source.
		/// </summary>
		/// <returns>
		/// The password for the specified user name.
		/// </returns>
		/// <param name="username">The user to retrieve the password for. </param><param name="answer">The password answer for the user. </param>
		public override string GetPassword(string username, string answer)
		{
			if (!this.EnablePasswordRetrieval)
			{
				this.HandleExceptionAndThrow(new MongoProviderException("Password Retrieval is not enabled."));
			}

			User user = this.GetUserByName(username);
			if (user == null)
			{
				this.HandleExceptionAndThrow(new MongoProviderException("User was not found."));
			}

			if (user.IsLockedOut)
			{
				this.HandleExceptionAndThrow(new MongoProviderException(string.Format("User is locked out. user id: {0}", user.Id)));
			}

			var decodedCorrectAnswer = user.PasswordAnswer.Decode(user.PasswordFormat);
			var decodedAnswer = answer.Decode(user.PasswordFormat);

			if (this.RequiresQuestionAndAnswer && decodedCorrectAnswer == decodedAnswer)
			{
				this.UpdateFailurePasswordAnswerCount(user, false);
				this.HandleExceptionAndThrow(new MongoProviderException(string.Format("Wrong answer, user id: {0}.", user.Id)));
			}

			return user.Password.Decode(user.PasswordFormat);
		}

		/// <summary>
		/// Processes a request to update the password for a membership user.
		/// </summary>
		/// <returns>
		/// true if the password was updated successfully; otherwise, false.
		/// </returns>
		/// <param name="username">The user to update the password for. </param><param name="oldPassword">The current password for the specified user. </param><param name="newPassword">The new password for the specified user. </param>
		public override bool ChangePassword(string username, string oldPassword, string newPassword)
		{
			if (string.IsNullOrEmpty(username) || this.InvalidUsernameCharacters.Any(username.Contains) || username.Length > MaxUsernameLength)
			{
				return false;
			}

			if (string.IsNullOrEmpty(oldPassword) || oldPassword.Length > MaxPasswordLength || oldPassword.Length < this.MinRequiredPasswordLength)
			{
				return false;
			}

			User user = this.GetUserByName(username);
			if (user == null)
			{
				this.HandleExceptionAndThrow(new MongoProviderException("User was not found."));
			}
			if (user.IsLockedOut)
			{
				this.HandleExceptionAndThrow(new MongoProviderException(string.Format("User is locked out. user id: {0}", user.Id)));
			}

			if (!this.ValidateUserPassword(user, oldPassword))
			{
				return false;
			}

			if (string.IsNullOrEmpty(newPassword) || newPassword.Length > MaxPasswordLength || newPassword.Length < this.MinRequiredPasswordLength)
			{
				return false;
			}
			if (!string.IsNullOrEmpty(this.PasswordStrengthRegularExpression) && !Regex.IsMatch(newPassword, this.PasswordStrengthRegularExpression))
			{
				return false;
			}

			if (this.MinRequiredNonAlphanumericCharacters > 0)
			{
				int numNonAlphaNumericChars = newPassword.Where((t, i) => !char.IsLetterOrDigit(newPassword, i)).Count();

				if (numNonAlphaNumericChars < this.MinRequiredNonAlphanumericCharacters)
				{
					return false;
				}
			}

			// Raise event to let others check new username/password
			ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(username, newPassword, false);
			this.OnValidatingPassword(args);
			if (args.Cancel)
			{
				if (args.FailureInformation != null)
				{
					throw args.FailureInformation;
				}
				throw new MembershipPasswordException("Change password canceled due to new password validation failure.");
			}

			// Save new password
			user.Password = newPassword.Encode(this.PasswordFormat);
			user.PasswordFormat = this.PasswordFormat;
			user.LastPasswordChangedDate = DateTime.UtcNow;
			this.SaveUser(user);

			return true;
		}

		/// <summary>
		/// Resets a user's password to a new, automatically generated password.
		/// </summary>
		/// <returns>
		/// The new password for the specified user.
		/// </returns>
		/// <param name="username">The user to reset the password for. </param><param name="answer">The password answer for the specified user. </param>
		public override string ResetPassword(string username, string answer)
		{
			if (!this.EnablePasswordReset)
			{
				throw new NotSupportedException("Password reset is not enabled.");
			}

			User user = this.GetUserByName(username);
			if (user == null)
			{
				this.HandleExceptionAndThrow(new MongoProviderException("User was not found."));
			}
			if (user.IsLockedOut)
			{
				this.HandleExceptionAndThrow(new MongoProviderException(string.Format("User is locked out. user id: {0}", user.Id)));
			}

			var decodedCorrectAnswer = user.PasswordAnswer.Decode(user.PasswordFormat);
			var decodedAnswer = answer.Decode(user.PasswordFormat);

			if (this.RequiresQuestionAndAnswer && decodedCorrectAnswer == decodedAnswer)
			{
				this.UpdateFailurePasswordAnswerCount(user, false);
				this.HandleExceptionAndThrow(new MongoProviderException(string.Format("Wrong answer, user id: {0}.", user.Id)));
			}

			string newGeneratedPassword = Membership.GeneratePassword(NewPasswordLength, this.MinRequiredNonAlphanumericCharacters);

			// Raise event to let others check new username/password
			ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(username, newGeneratedPassword, false);
			this.OnValidatingPassword(args);
			if (args.Cancel)
			{
				if (args.FailureInformation != null)
				{
					throw args.FailureInformation;
				}
				throw new MembershipPasswordException("Change password canceled due to new password validation failure.");
			}

			// Save new password
			user.Password = newGeneratedPassword.Decode(this.PasswordFormat);
			user.PasswordFormat = this.PasswordFormat;
			user.LastPasswordChangedDate = DateTime.UtcNow;
			this.SaveUser(user);

			return newGeneratedPassword;
		}

		/// <summary>
		/// Updates information about a user in the data source.
		/// </summary>
		/// <param name="user">A <see cref="T:System.Web.Security.MembershipUser"/> object that represents the user to update and the updated information for the user. </param>
		public override void UpdateUser(MembershipUser user)
		{
			User userFromDB = this.GetUserById(BsonValue.Create(user.ProviderUserKey));
			if (userFromDB == null)
			{
				this.HandleExceptionAndThrow(new MongoProviderException("User was not found."));
			}
			if (userFromDB.IsLockedOut)
			{
				this.HandleExceptionAndThrow(new MongoProviderException(string.Format("User is locked out. user id: {0}", userFromDB.Id)));
			}

			userFromDB.Email = user.Email;
			userFromDB.Comment = user.Comment;
			userFromDB.IsApproved = user.IsApproved;
			userFromDB.LastLoginDate = user.LastLoginDate;
			userFromDB.LastActivityDate = user.LastActivityDate;
			this.SaveUser(userFromDB);
		}

		/// <summary>
		/// Verifies that the specified user name and password exist in the data source.
		/// </summary>
		/// <returns>
		/// true if the specified username and password are valid; otherwise, false.
		/// </returns>
		/// <param name="username">The name of the user to validate. </param><param name="password">The password for the specified user. </param>
		public override bool ValidateUser(string username, string password)
		{
			if (string.IsNullOrEmpty(username) || this.InvalidUsernameCharacters.Any(username.Contains) || username.Length > MaxUsernameLength)
			{
				return false;
			}

			if (string.IsNullOrEmpty(password) || password.Length > MaxPasswordLength || password.Length < this.MinRequiredPasswordLength)
			{
				return false;
			}

			User user = this.GetUserByName(username);
			if (user == null || user.IsLockedOut || !user.IsApproved)
			{
				return false;
			}

			if (!this.ValidateUserPassword(user, password))
			{
				return false;
			}

			// User is authenticated. Update last activity and last login dates and failure counts.
			user.LastActivityDate = DateTime.UtcNow;
			user.LastLoginDate = DateTime.UtcNow;
			user.FailedPasswordAnswerAttemptCount = 0;
			user.FailedPasswordAttemptCount = 0;
			user.FailedPasswordAnswerAttemptWindowStart = DateTime.MinValue;
			user.FailedPasswordAttemptWindowStart = DateTime.MinValue;
			this.SaveUser(user);

			return true;
		}

		/// <summary>
		/// Clears a lock so that the membership user can be validated.
		/// </summary>
		/// <param name="username">The username.</param>
		/// <returns>
		/// true if the membership user was successfully unlocked; otherwise, false.
		/// </returns>
		public override bool UnlockUser(string username)
		{
			User user = this.GetUserByName(username);
			if (user == null || !user.IsApproved)
			{
				return false;
			}

			user.IsLockedOut = false;
			user.LastActivityDate = DateTime.UtcNow;
			user.LastLoginDate = DateTime.UtcNow;
			user.FailedPasswordAnswerAttemptCount = 0;
			user.FailedPasswordAttemptCount = 0;
			user.FailedPasswordAnswerAttemptWindowStart = DateTime.MinValue;
			user.FailedPasswordAttemptWindowStart = DateTime.MinValue;
			this.SaveUser(user);

			return true;
		}

		/// <summary>
		/// Gets user information from the data source based on the unique identifier for the membership user. Provides an option to update the last-activity date/time stamp for the user.
		/// </summary>
		/// <returns>
		/// A <see cref="T:System.Web.Security.MembershipUser"/> object populated with the specified user's information from the data source.
		/// </returns>
		/// <param name="providerUserKey">The unique identifier for the membership user to get information for.</param><param name="userIsOnline">true to update the last-activity date/time stamp for the user; false to return user information without updating the last-activity date/time stamp for the user.</param>
		public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
		{
			var id = providerUserKey is BsonValue ? providerUserKey as BsonValue : BsonValue.Create(providerUserKey);
			var user = this.GetUserById(id);
			return this.ToMembershipUser(user);
		}

		/// <summary>
		/// Gets information from the data source for a user. Provides an option to update the last-activity date/time stamp for the user.
		/// </summary>
		/// <returns>
		/// A <see cref="T:System.Web.Security.MembershipUser"/> object populated with the specified user's information from the data source.
		/// </returns>
		/// <param name="username">The name of the user to get information for. </param><param name="userIsOnline">true to update the last-activity date/time stamp for the user; false to return user information without updating the last-activity date/time stamp for the user. </param>
		public override MembershipUser GetUser(string username, bool userIsOnline)
		{
			var user = this.GetUserByName(username);
			return this.ToMembershipUser(user);
		}

		/// <summary>
		/// Gets the user name associated with the specified e-email address.
		/// </summary>
		/// <returns>
		/// The user name associated with the specified e-email address. If no match is found, return null.
		/// </returns>
		/// <param name="email">The e-email address to search for. </param>
		public override string GetUserNameByEmail(string email)
		{
			var user = this.GetUserByMail(email);
			return user.UserName;
		}

		/// <summary>
		/// Removes a user from the membership data source. 
		/// </summary>
		/// <returns>
		/// true if the user was successfully deleted; otherwise, false.
		/// </returns>
		/// <param name="username">The name of the user to delete.</param><param name="deleteAllRelatedData">true to delete data related to the user from the database; false to leave data related to the user in the database.</param>
		public override bool DeleteUser(string username, bool deleteAllRelatedData)
		{
			if (string.IsNullOrEmpty(username))
			{
				return false;
			}

			var query = Query.EQ(Utils.GetElementNameFor<User>(u => u.LowercaseUsername), username.ToLowerInvariant());
			var result = this.UsersCollection.Remove(query, SafeMode.True);
			return result.Ok;
		}

		/// <summary>
		/// Gets a collection of all the users in the data source in pages of data.
		/// </summary>
		/// <returns>
		/// A <see cref="T:System.Web.Security.MembershipUserCollection"/> collection that contains a page of <paramref name="pageSize"/><see cref="T:System.Web.Security.MembershipUser"/> objects beginning at the page specified by <paramref name="pageIndex"/>.
		/// </returns>
		/// <param name="pageIndex">The index of the page of results to return. <paramref name="pageIndex"/> is zero-based.</param><param name="pageSize">The size of the page of results to return.</param><param name="totalRecords">The total number of matched users.</param>
		public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
		{
			var users = new MembershipUserCollection();

			// execute second query to get total count
			totalRecords = (int)this.UsersCollection.Count();
			if (totalRecords == 0 || pageIndex <= 0 || pageSize <= 0)
			{
				return users;
			}

			this.UsersCollection.AsQueryable()
				.Skip(pageIndex * pageSize)
				.Take(pageSize)
				.Select(u => this.ToMembershipUser(u))
				.ToList()
				.ForEach(users.Add);

			return users;
		}

		/// <summary>
		/// Gets the number of users currently accessing the application.
		/// http://msdn.microsoft.com/en-us/library/system.web.security.membership.userisonlinetimewindow.aspx
		/// </summary>
		/// <returns>
		/// The number of users currently accessing the application.
		/// </returns>
		public override int GetNumberOfUsersOnline()
		{
			TimeSpan onlineSpan = new TimeSpan(0, Membership.UserIsOnlineTimeWindow, 0);
			DateTime compareTime = DateTime.UtcNow.Subtract(onlineSpan);

			return this.UsersCollection.AsQueryable().Count(u => u.LastActivityDate > compareTime);
		}

		/// <summary>
		/// Gets a collection of membership users where the user name contains the specified user name to match.
		/// </summary>
		/// <returns>
		/// A <see cref="T:System.Web.Security.MembershipUserCollection"/> collection that contains a page of <paramref name="pageSize"/><see cref="T:System.Web.Security.MembershipUser"/> objects beginning at the page specified by <paramref name="pageIndex"/>.
		/// </returns>
		/// <param name="usernameToMatch">The user name to search for.</param><param name="pageIndex">The index of the page of results to return. <paramref name="pageIndex"/> is zero-based.</param><param name="pageSize">The size of the page of results to return.</param><param name="totalRecords">The total number of matched users.</param>
		public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
		{
			var users = new MembershipUserCollection();

			if (pageIndex <= 0 || pageSize <= 0)
			{
				totalRecords = 0;
				return users;
			}

			var usersToMatchQuery = this.UsersCollection.AsQueryable()
															.Where(u => u.LowercaseUsername == usernameToMatch.ToLowerInvariant());

			totalRecords = usersToMatchQuery.Count();

			usersToMatchQuery
				.Skip(pageIndex * pageSize)
				.Take(pageSize)
				.Select(u => this.ToMembershipUser(u))
				.ToList()
				.ForEach(users.Add);

			return users;
		}

		/// <summary>
		/// Gets a collection of membership users where the e-email address contains the specified e-email address to match.
		/// </summary>
		/// <returns>
		/// A <see cref="T:System.Web.Security.MembershipUserCollection"/> collection that contains a page of <paramref name="pageSize"/><see cref="T:System.Web.Security.MembershipUser"/> objects beginning at the page specified by <paramref name="pageIndex"/>.
		/// </returns>
		/// <param name="emailToMatch">The e-email address to search for.</param><param name="pageIndex">The index of the page of results to return. <paramref name="pageIndex"/> is zero-based.</param><param name="pageSize">The size of the page of results to return.</param><param name="totalRecords">The total number of matched users.</param>
		public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
		{
			var users = new MembershipUserCollection();

			if (pageIndex <= 0 || pageSize <= 0)
			{
				totalRecords = 0;
				return users;
			}

			var usersToMatchQuery = this.UsersCollection.AsQueryable()
															.Where(u => u.LowercaseEmail == emailToMatch.ToLowerInvariant());

			totalRecords = usersToMatchQuery.Count();

			usersToMatchQuery
				.Skip(pageIndex * pageSize)
				.Take(pageSize)
				.Select(u => this.ToMembershipUser(u))
				.ToList()
				.ForEach(users.Add);

			return users;
		}

		#endregion
		#region Overrides of MembershipProvider Properties

		/// <summary>
		/// Indicates whether the membership provider is configured to allow users to retrieve their passwords.
		/// </summary>
		/// <returns>
		/// true if the membership provider is configured to support password retrieval; otherwise, false. The default is false.
		/// </returns>
		public override bool EnablePasswordRetrieval
		{
			get { return this.enablePasswordRetrieval; }
		}

		/// <summary>
		/// Indicates whether the membership provider is configured to allow users to reset their passwords.
		/// </summary>
		/// <returns>
		/// true if the membership provider supports password reset; otherwise, false. The default is true.
		/// </returns>
		public override bool EnablePasswordReset
		{
			get { return this.enablePasswordReset; }
		}

		/// <summary>
		/// Gets a value indicating whether the membership provider is configured to require the user to answer a password question for password reset and retrieval.
		/// </summary>
		/// <returns>
		/// true if a password answer is required for password reset and retrieval; otherwise, false. The default is true.
		/// </returns>
		public override bool RequiresQuestionAndAnswer
		{
			get { return this.requiresQuestionAndAnswer; }
		}

		/// <summary>
		/// The name of the application using the custom membership provider.
		/// </summary>
		/// <returns>
		/// The name of the application using the custom membership provider.
		/// </returns>
		public override string ApplicationName
		{
			get { return this.applicationName; }
			set { this.applicationName = value; }
		}

		/// <summary>
		/// Gets the number of invalid password or password-answer attempts allowed before the membership user is locked out.
		/// </summary>
		/// <returns>
		/// The number of invalid password or password-answer attempts allowed before the membership user is locked out.
		/// </returns>
		public override int MaxInvalidPasswordAttempts
		{
			get { return this.maxInvalidPasswordAttempts; }
		}

		/// <summary>
		/// Gets the number of minutes in which a maximum number of invalid password or password-answer attempts are allowed before the membership user is locked out.
		/// </summary>
		/// <returns>
		/// The number of minutes in which a maximum number of invalid password or password-answer attempts are allowed before the membership user is locked out.
		/// </returns>
		public override int PasswordAttemptWindow
		{
			get { return this.passwordAttemptWindow; }
		}

		/// <summary>
		/// Gets a value indicating whether the membership provider is configured to require a unique e-email address for each user name.
		/// </summary>
		/// <returns>
		/// true if the membership provider requires a unique e-email address; otherwise, false. The default is true.
		/// </returns>
		public override bool RequiresUniqueEmail
		{
			get { return this.requiresUniqueEmail; }
		}

		/// <summary>
		/// Gets a value indicating the format for storing passwords in the membership data store.
		/// </summary>
		/// <returns>
		/// One of the <see cref="T:System.Web.Security.MembershipPasswordFormat"/> values indicating the format for storing passwords in the data store.
		/// </returns>
		public override MembershipPasswordFormat PasswordFormat
		{
			get { return this.passwordFormat; }
		}

		/// <summary>
		/// Gets the minimum length required for a password.
		/// </summary>
		/// <returns>
		/// The minimum length required for a password. 
		/// </returns>
		public override int MinRequiredPasswordLength
		{
			get { return this.minRequiredPasswordLength; }
		}

		/// <summary>
		/// Gets the minimum number of special characters that must be present in a valid password.
		/// </summary>
		/// <returns>
		/// The minimum number of special characters that must be present in a valid password.
		/// </returns>
		public override int MinRequiredNonAlphanumericCharacters
		{
			get { return this.minRequiredNonAlphanumericCharacters; }
		}

		/// <summary>
		/// Gets the regular expression used to evaluate a password.
		/// </summary>
		/// <returns>
		/// A regular expression used to evaluate a password.
		/// </returns>
		public override string PasswordStrengthRegularExpression
		{
			get { return this.passwordStrengthRegularExpression; }
		}

		#endregion

		protected virtual void RegigisterMaps()
		{
			new UserBsonMap();
		}

		protected virtual void InitMongoDB()
		{
			this.Database = MongoDatabase.Create(this.connectionString);
			this.CollectionName = this.usersCollectionName;
			this.UsersCollection = Database.GetCollection<User>(CollectionName);

			DateTimeSerializationOptions.Defaults = DateTimeSerializationOptions.LocalInstance;
		}

		protected virtual User GetUserByMail(string email)
		{
			if (string.IsNullOrEmpty(email))
			{
				this.HandleExceptionAndThrow(new MongoProviderException(new ArgumentNullException("email")));
			}

			return this.UsersCollection.AsQueryable().FirstOrDefault(u => u.LowercaseEmail == email.ToLowerInvariant());
		}

		protected virtual User GetUserByName(string userName)
		{
			if (string.IsNullOrEmpty(userName))
			{
				this.HandleExceptionAndThrow(new MongoProviderException(new ArgumentException("userName")));
			}

			return this.UsersCollection.AsQueryable().FirstOrDefault(u => u.LowercaseUsername == userName.ToLowerInvariant());
		}

		protected virtual User GetUserById(BsonValue id)
		{
			if (id == null)
			{
				this.HandleExceptionAndThrow(new MongoProviderException(new ArgumentNullException("id")));
			}

			return this.UsersCollection.FindOneById(id);
		}

		protected virtual void SaveUser<T>(T user) where T : User
		{
			SafeModeResult result = null;
			try
			{
				var users = this.UsersCollection;
				result = users.Save(user, SafeMode.True);
			}
			catch (Exception exception)
			{
				this.HandleExceptionAndThrow(new MongoProviderException(exception));
			}

			if (result == null)
			{
				this.HandleExceptionAndThrow(new MongoProviderException("SaveUser to database did not return a status result"));
			}
			else if (!result.Ok)
			{
				this.HandleExceptionAndThrow(new MongoProviderException(result.LastErrorMessage));
			}
		}

		protected virtual void HandleExceptionAndThrow(MongoProviderException exception)
		{
			if (this.WriteExceptionsToEventLog)
			{
				var log = new EventLog { Source = EventSource, Log = EventLog };
				var message = string.Format("An exception occurred communicating with the data source.\r\n Exception: {0}", exception);
				log.WriteEntry(message);
			}

			throw exception;
		}

		protected virtual MembershipUser ToMembershipUser<T>(T user) where T : User
		{
			if (user == null)
			{
				return null;
			}

			return new MembershipUser(this.Name, user.UserName, user.Id, user.Email, user.PasswordQuestion, user.Comment, user.IsApproved,
				user.IsLockedOut, user.CreationDate, user.LastLoginDate, user.LastActivityDate, user.LastPasswordChangedDate, user.LastLockoutDate);
		}

		protected virtual bool ValidateUserPassword(User user, string password)
		{
			if (user == null || !user.IsApproved || user.IsLockedOut)
			{
				return false;
			}

			string encodedPassword = password.Encode(user.PasswordFormat);

			bool isValidPassword = user.Password.Equals(encodedPassword);

			if (isValidPassword && user.FailedPasswordAttemptCount == 0)
			{
				return true;
			}

			return this.UpdateFailurePasswordCount(user, isValidPassword);
		}

		protected virtual bool UpdateFailurePasswordCount(User user, bool isAuthenticated)
		{
			if (user == null || user.IsLockedOut)
			{
				return isAuthenticated;
			}

			if (isAuthenticated && user.FailedPasswordAttemptCount > 0)
			{
				user.FailedPasswordAttemptCount = 0;
				user.FailedPasswordAttemptWindowStart = DateTime.UtcNow;
				this.SaveUser(user);
				return true;
			}

			var windowStart = user.FailedPasswordAttemptWindowStart;
			var windowEnd = windowStart.AddMinutes(this.PasswordAttemptWindow);
			var failureCount = user.FailedPasswordAttemptCount;

			if (failureCount == 0 || DateTime.UtcNow > windowEnd)
			{
				user.FailedPasswordAttemptCount = 1;
				user.FailedPasswordAttemptWindowStart = DateTime.UtcNow;
				this.SaveUser(user);
				return isAuthenticated;
			}

			// Password attempts have exceeded the failure threshold. Lock out the user.
			if (++failureCount >= this.MaxInvalidPasswordAttempts)
			{
				user.IsLockedOut = true;
				user.LastLockoutDate = DateTime.UtcNow;
				user.FailedPasswordAttemptCount = failureCount;
				this.SaveUser(user);
				return isAuthenticated;
			}

			// Password attempts have not exceeded the failure threshold. Update the failure counts. Leave the window the same.
			user.FailedPasswordAttemptCount = failureCount;
			this.SaveUser(user);
			return isAuthenticated;
		}

		protected virtual bool UpdateFailurePasswordAnswerCount(User user, bool isAuthenticated)
		{
			if (user == null || user.IsLockedOut)
			{
				return isAuthenticated;
			}

			if (isAuthenticated && user.FailedPasswordAnswerAttemptCount > 0)
			{
				user.FailedPasswordAnswerAttemptCount = 0;
				user.FailedPasswordAnswerAttemptWindowStart = DateTime.UtcNow;
				this.SaveUser(user);
				return true;
			}

			var windowStart = user.FailedPasswordAnswerAttemptWindowStart;
			var windowEnd = windowStart.AddMinutes(this.PasswordAttemptWindow);
			var failureCount = user.FailedPasswordAnswerAttemptCount;

			if (failureCount == 0 || DateTime.UtcNow > windowEnd)
			{
				user.FailedPasswordAnswerAttemptCount = 1;
				user.FailedPasswordAnswerAttemptWindowStart = DateTime.UtcNow;
				this.SaveUser(user);
				return isAuthenticated;
			}

			// Password attempts have exceeded the failure threshold. Lock out the user.
			if (++failureCount >= this.MaxInvalidPasswordAttempts)
			{
				user.IsLockedOut = true;
				user.LastLockoutDate = DateTime.UtcNow;
				user.FailedPasswordAnswerAttemptCount = failureCount;
				this.SaveUser(user);
				return isAuthenticated;
			}

			// Password attempts have not exceeded the failure threshold. Update the failure counts. Leave the window the same.
			user.FailedPasswordAnswerAttemptCount = failureCount;
			this.SaveUser(user);
			return isAuthenticated;
		}
	}
}
