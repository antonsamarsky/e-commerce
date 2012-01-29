using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Configuration;
using System.Web.Security;
using Bikee.Security.Domain;
using FluentMongo.Linq;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
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
		private int newPasswordLength = 8;
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
		public const int NewPasswordLength = 8;
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

		#region Overrides of MembershipProvider

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
			if (config == null)
			{
				throw new ArgumentNullException("config");
			}

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
					throw new ProviderException("Password format not supported.");
			}

			if ((this.passwordFormat == MembershipPasswordFormat.Hashed) && EnablePasswordRetrieval)
			{
				throw new ProviderException("Configured settings are invalid: Hashed passwords cannot be retrieved. Either set the password format to different type, or set supportsPasswordRetrieval to false.");
			}

			var connectionStringSettings = ConfigurationManager.ConnectionStrings[config["connectionStringName"]];
			if (connectionStringSettings == null || string.IsNullOrEmpty(connectionStringSettings.ConnectionString.Trim()))
			{
				throw new ProviderException("Connection string cannot be blank.");
			}

			this.connectionString = connectionStringSettings.ConnectionString;

			// Get encryption and decryption key information from the configuration.
			this.machineKey = (MachineKeySection)ConfigurationManager.GetSection("system.web/machineKey");
			//var webConfig = WebConfigurationManager.OpenWebConfiguration(System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
			//this.machineKey = (MachineKeySection)webConfig.GetSection("system.web/machineKey");

			if (this.machineKey == null)
			{
				throw new ProviderException("Machine key is not set");
			}

			if (this.machineKey.ValidationKey.Contains("AutoGenerate") && this.PasswordFormat != MembershipPasswordFormat.Clear)
			{
				throw new ProviderException("Hashed or Encrypted passwords are not supported with auto-generated keys.");
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
		/// <param name="username">The user name for the new user. </param><param name="password">The password for the new user. </param><param name="email">The e-mail address for the new user.</param><param name="passwordQuestion">The password question for the new user.</param><param name="passwordAnswer">The password answer for the new user</param><param name="isApproved">Whether or not the new user is approved to be validated.</param><param name="providerUserKey">The unique identifier from the membership data source for the user.</param><param name="status">A <see cref="T:System.Web.Security.MembershipCreateStatus"/> enumeration value indicating whether the user was created successfully.</param>
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
				Password = this.Encode(password),
				PasswordQuestion = passwordQuestion,
				PasswordAnswer = this.Encode(passwordAnswer),
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

			this.Save(user);

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
			throw new System.NotImplementedException();
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
			throw new System.NotImplementedException();
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
			throw new System.NotImplementedException();
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
			throw new System.NotImplementedException();
		}

		/// <summary>
		/// Updates information about a user in the data source.
		/// </summary>
		/// <param name="user">A <see cref="T:System.Web.Security.MembershipUser"/> object that represents the user to update and the updated information for the user. </param>
		public override void UpdateUser(MembershipUser user)
		{
			throw new System.NotImplementedException();
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
			throw new System.NotImplementedException();
		}

		/// <summary>
		/// Clears a lock so that the membership user can be validated.
		/// </summary>
		/// <returns>
		/// true if the membership user was successfully unlocked; otherwise, false.
		/// </returns>
		/// <param name="userName">The membership user whose lock status you want to clear.</param>
		public override bool UnlockUser(string userName)
		{
			throw new System.NotImplementedException();
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
			if (providerUserKey == null)
			{
				throw new ArgumentNullException("providerUserKey");
			}

			var id = providerUserKey is BsonValue ? providerUserKey as BsonValue : BsonValue.Create(providerUserKey);

			if (id == null)
			{
				throw new ArgumentException("providerUserKey type should be compatible with BsonValue type");
			}

			var user = this.UsersCollection.FindOneById(id);
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
			if (string.IsNullOrEmpty(username))
			{
				throw new ArgumentException("username");
			}

				var user = this.UsersCollection.AsQueryable().FirstOrDefault(u => u.LowercaseUsername == username.ToLowerInvariant());
				return this.ToMembershipUser(user);
		}

		/// <summary>
		/// Gets the user name associated with the specified e-mail address.
		/// </summary>
		/// <returns>
		/// The user name associated with the specified e-mail address. If no match is found, return null.
		/// </returns>
		/// <param name="email">The e-mail address to search for. </param>
		public override string GetUserNameByEmail(string email)
		{
			return string.Empty;
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
			throw new System.NotImplementedException();
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
			throw new System.NotImplementedException();
		}

		/// <summary>
		/// Gets the number of users currently accessing the application.
		/// </summary>
		/// <returns>
		/// The number of users currently accessing the application.
		/// </returns>
		public override int GetNumberOfUsersOnline()
		{
			throw new System.NotImplementedException();
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
			throw new System.NotImplementedException();
		}

		/// <summary>
		/// Gets a collection of membership users where the e-mail address contains the specified e-mail address to match.
		/// </summary>
		/// <returns>
		/// A <see cref="T:System.Web.Security.MembershipUserCollection"/> collection that contains a page of <paramref name="pageSize"/><see cref="T:System.Web.Security.MembershipUser"/> objects beginning at the page specified by <paramref name="pageIndex"/>.
		/// </returns>
		/// <param name="emailToMatch">The e-mail address to search for.</param><param name="pageIndex">The index of the page of results to return. <paramref name="pageIndex"/> is zero-based.</param><param name="pageSize">The size of the page of results to return.</param><param name="totalRecords">The total number of matched users.</param>
		public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
		{
			throw new System.NotImplementedException();
		}

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
		/// Gets a value indicating whether the membership provider is configured to require a unique e-mail address for each user name.
		/// </summary>
		/// <returns>
		/// true if the membership provider requires a unique e-mail address; otherwise, false. The default is true.
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

		/// <summary>
		/// Encodes the password. Encrypts, Hashes, or leaves the password clear based on the PasswordFormat.
		/// </summary>
		/// <param name="stringToBeEncoded">The string to be encoded.</param>
		/// <returns>
		/// The encoded password.
		/// </returns>
		protected string Encode(string stringToBeEncoded)
		{
			if (string.IsNullOrEmpty(stringToBeEncoded))
			{
				return null;
			}

			byte[] passwordData;
			string encodedString = stringToBeEncoded;
			switch (this.PasswordFormat)
			{
				case MembershipPasswordFormat.Clear:
					break;
				case MembershipPasswordFormat.Encrypted:
					passwordData = Encoding.Unicode.GetBytes(encodedString);
					encodedString = MachineKey.Encode(passwordData, MachineKeyProtection.All);
					break;
				case MembershipPasswordFormat.Hashed:
					passwordData = Encoding.Unicode.GetBytes(encodedString);
					encodedString = MachineKey.Encode(passwordData, MachineKeyProtection.Validation);
					break;
				default:
					throw new ProviderException("Unsupported password format.");
			}

			return encodedString;
		}

		/// <summary>
		/// Decodes the password. Decrypts or leaves the password clear based on the PasswordFormat.
		/// </summary>
		/// <param name="stringToBeDecoded">The string to be decoded.</param>
		/// <returns></returns>
		protected string Decode(string stringToBeDecoded)
		{
			string dencodedString = stringToBeDecoded;
			switch (this.PasswordFormat)
			{
				case MembershipPasswordFormat.Clear:
					break;
				case MembershipPasswordFormat.Encrypted:
					dencodedString = Encoding.Unicode.GetString(MachineKey.Decode(dencodedString, MachineKeyProtection.All));
					break;
				case MembershipPasswordFormat.Hashed:
					dencodedString = Encoding.Unicode.GetString(MachineKey.Decode(dencodedString, MachineKeyProtection.Validation));
					break;
				default:
					throw new ProviderException("Unsupported password format.");
			}

			return dencodedString;
		}

		protected void Save<T>(T user) where T : User
		{
			SafeModeResult result = null;
			try
			{
				var users = this.UsersCollection;
				result = users.Save(user, SafeMode.True);
			}
			catch (Exception exception)
			{
				this.HandleDataExceptionAndThrow(exception);
			}

			if (result == null)
			{
				this.HandleDataExceptionAndThrow(new ProviderException("Save to database did not return a status result"));
			}
			else if (!result.Ok)
			{
				this.HandleDataExceptionAndThrow(new ProviderException(result.LastErrorMessage));
			}
		}

		protected void HandleDataExceptionAndThrow(Exception exception)
		{
			if (this.WriteExceptionsToEventLog)
			{
				this.WriteToEventLog(exception);
				throw new ProviderException(exception.Message, exception);
			}

			throw exception;
		}

		/// <summary>
		/// WriteToEventLog
		/// A helper function that writes exception detail to the event log. Exceptions
		/// are written to the event log as a security measure to avoid private database
		/// details from being returned to the browser. If a method does not return a status
		/// or boolean indicating the action succeeded or failed, a generic exception is also
		/// thrown by the caller.
		/// </summary>
		/// <param name="exception">The exception.</param>
		protected void WriteToEventLog(Exception exception)
		{
			var log = new EventLog { Source = EventSource, Log = EventLog };

			var message = string.Format("An exception occurred communicating with the data source.\r\n Exception: {0}", exception);
			log.WriteEntry(message);
		}

		protected virtual MembershipUser ToMembershipUser<T>(T user) where T: User
		{
			if (user == null)
			{
				return null;
			}

			return new MembershipUser(this.Name, user.UserName, user.Id, user.Email, user.PasswordQuestion, user.Comment, user.IsApproved, 
				user.IsLockedOut, user.CreationDate, user.LastLoginDate, user.LastActivityDate, user.LastPasswordChangedDate,user.LastLockoutDate);
		}
	}
}
