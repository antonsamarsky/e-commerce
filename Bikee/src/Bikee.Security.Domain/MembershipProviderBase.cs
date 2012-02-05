using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web.Configuration;
using System.Web.Security;

namespace Bikee.Security.Domain
{
	// How to: Sample Membership Provider Implementation :
	// http://msdn.microsoft.com/en-us/library/ie/6tc47t75.aspx
	public abstract class MembershipProviderBase : MembershipProvider
	{
		#region Consts

		private const int MaxUsernameLength = 50;
		private const int MaxPasswordLength = 100;
		private const int MaxPasswordAnswerLength = 128;
		private const int MaxEmailLength = 50;
		private const int MaxPasswordQuestionLength = 256;

		#endregion

		#region Fields

		private string applicationName;
		private int maxInvalidPasswordAttempts;
		private int passwordAttemptWindow;
		private int minRequiredNonAlphanumericCharacters;
		private int minRequiredPasswordLength;
		private string passwordStrengthRegularExpression;
		private bool enablePasswordReset;
		private bool enablePasswordRetrieval;
		private bool requiresQuestionAndAnswer;
		private bool requiresUniqueEmail;
		private MembershipPasswordFormat passwordFormat;

		#endregion

		#region Properties

		protected bool WriteExceptionsToEventLog { get; set; }
		protected string InvalidUsernameCharacters { get; private set; }
		protected string InvalidEmailCharacters { get; private set; }
		protected string ConnectionString { get; private set; }

		#endregion

		#region Overrides of Properties

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

			this.applicationName = SecurityHelper.GetConfigValue(config["applicationName"], System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
			this.maxInvalidPasswordAttempts = SecurityHelper.GetConfigValue(config["maxInvalidPasswordAttempts"], 5);
			this.passwordAttemptWindow = SecurityHelper.GetConfigValue(config["passwordAttemptWindow"], 10);
			this.minRequiredNonAlphanumericCharacters = SecurityHelper.GetConfigValue(config["minRequiredNonAlphanumericCharacters"], 1);
			this.minRequiredPasswordLength = SecurityHelper.GetConfigValue(config["minRequiredPasswordLength"], 7);
			this.passwordStrengthRegularExpression = SecurityHelper.GetConfigValue(config["passwordStrengthRegularExpression"], string.Empty);
			this.enablePasswordReset = SecurityHelper.GetConfigValue(config["enablePasswordReset"], true);
			this.enablePasswordRetrieval = SecurityHelper.GetConfigValue(config["enablePasswordRetrieval"], false);
			this.requiresQuestionAndAnswer = SecurityHelper.GetConfigValue(config["requiresQuestionAndAnswer"], false);
			this.requiresUniqueEmail = SecurityHelper.GetConfigValue(config["requiresUniqueEmail"], true);

			this.InvalidUsernameCharacters = SecurityHelper.GetConfigValue(config["invalidUsernameCharacters"], ",%\"/{}()''");
			this.InvalidEmailCharacters = SecurityHelper.GetConfigValue(config["invalidEmailCharacters"], ",%\"/{}()''");
			this.WriteExceptionsToEventLog = SecurityHelper.GetConfigValue(config["writeExceptionsToEventLog"], true);

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

			if ((this.passwordFormat == MembershipPasswordFormat.Hashed) && this.EnablePasswordRetrieval)
			{
				throw new ProviderException("Configured settings are invalid: Hashed passwords cannot be retrieved. Either set the password format to different type, or set supportsPasswordRetrieval to false.");
			}

			var connectionStringSettings = ConfigurationManager.ConnectionStrings[config["connectionStringName"]];
			if (connectionStringSettings == null || string.IsNullOrEmpty(connectionStringSettings.ConnectionString.Trim()))
			{
				throw new ProviderException("Connection string cannot be blank.");
			}

			this.ConnectionString = connectionStringSettings.ConnectionString;

			var machineKey = (MachineKeySection)ConfigurationManager.GetSection("system.web/machineKey");
			if ((machineKey == null || machineKey.ValidationKey.Contains("AutoGenerate")) && this.PasswordFormat != MembershipPasswordFormat.Clear)
			{
				throw new ProviderException("Hashed or Encrypted passwords are not supported with auto-generated keys.");
			}
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
			var validatedUserName = this.ValidateUserName(username);
			if (validatedUserName == null)
			{
				status = MembershipCreateStatus.InvalidUserName;
				return null;
			}

			var validatedPassword = this.ValidatePassword(password);
			if (validatedPassword == null)
			{
				status = MembershipCreateStatus.InvalidPassword;
				return null;
			}

			var args = new ValidatePasswordEventArgs(validatedUserName, validatedPassword, true);
			this.OnValidatingPassword(args);

			if (args.Cancel)
			{
				status = MembershipCreateStatus.InvalidPassword;
				return null;
			}

			if (this.ValidateEmail(email) == null)
			{
				status = MembershipCreateStatus.InvalidEmail;
				return null;
			}

			if (this.ValidateQuestion(passwordQuestion) == null)
			{
				status = MembershipCreateStatus.InvalidQuestion;
				return null;
			}

			if (this.ValidateAnswer(passwordAnswer) == null)
			{
				status = MembershipCreateStatus.InvalidQuestion;
				return null;
			}

			if (this.GetUser(validatedUserName, false) != null)
			{
				status = MembershipCreateStatus.DuplicateUserName;
				return null;
			}

			if (this.RequiresUniqueEmail && !string.IsNullOrEmpty(this.GetUserNameByEmail(email)))
			{
				status = MembershipCreateStatus.DuplicateEmail;
				return null;
			}

			if (providerUserKey != null && this.GetUser(providerUserKey, false) != null)
			{
				status = MembershipCreateStatus.DuplicateProviderUserKey;
				return null;
			}

			status = MembershipCreateStatus.Success;
			return null;
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
			var validatedPasswordQuestion = this.ValidateQuestion(newPasswordQuestion);
			if (validatedPasswordQuestion == null)
			{
				return false;
			}

			var validatedPasswordAnswer = this.ValidateAnswer(newPasswordAnswer);
			if (validatedPasswordAnswer == null)
			{
				return false;
			}

			return this.ValidateUser(username, password);
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
				throw new NotSupportedException("Password Retrieval is not enabled.");
			}

			if (this.PasswordFormat == MembershipPasswordFormat.Hashed)
			{
				throw new NotSupportedException("Cannot retrieve hashed passwords.");
			}

			if (this.ValidateUserName(username) == null)
			{
				throw new ProviderException("Invalid user name.");
			}

			if (this.ValidateAnswer(answer) == null)
			{
				throw new ProviderException("Invalid answer.");
			}

			return string.Empty;
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
			// Raise event to let others check new username/password
			var args = new ValidatePasswordEventArgs(username, oldPassword, true);
			this.OnValidatingPassword(args);
			if (args.Cancel)
			{
				if (args.FailureInformation != null)
				{
					throw args.FailureInformation;
				}
				throw new MembershipPasswordException("Change password canceled due to new password validation failure.");
			}

			return this.ValidateUser(username, oldPassword);
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

			return string.Empty;
		}

		/// <summary>
		/// Updates information about a user in the data source.
		/// </summary>
		/// <param name="user">A <see cref="T:System.Web.Security.MembershipUser"/> object that represents the user to update and the updated information for the user. </param>
		public override void UpdateUser(MembershipUser user)
		{
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
			var validatedUserName = this.ValidateUserName(username);
			if (validatedUserName == null)
			{
				return false;
			}

			var validatedPassword = this.ValidatePassword(password);
			if (validatedPassword == null)
			{
				return false;
			}

			return true;
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
			var validatedUserName = this.ValidateUserName(userName);
			if (validatedUserName == null)
			{
				return false;
			}

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
			if (providerUserKey == null)
			{
				throw new ArgumentNullException("providerUserKey");
			}

			return null;
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
			if (this.ValidateUserName(username) == null)
			{
				throw new ArgumentException("username");
			}

			return null;
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
			if (this.ValidateEmail(email) == null)
			{
				throw new ArgumentException("email");
			}

			return null;
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
			if (this.ValidateUserName(username) == null)
			{
				return false;
			}

			return true;
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
			totalRecords = 0;
			return new MembershipUserCollection();
		}

		/// <summary>
		/// Gets the number of users currently accessing the application.
		/// </summary>
		/// <returns>
		/// The number of users currently accessing the application.
		/// </returns>
		public override int GetNumberOfUsersOnline()
		{
			return 0;
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
			if (this.ValidateUserName(usernameToMatch) == null)
			{
				throw new ArgumentException("usernameToMatch");
			}

			totalRecords = 0;
			return new MembershipUserCollection();
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
			if (this.ValidateEmail(emailToMatch) == null)
			{
				throw new ArgumentException("emailToMatch");
			}

			totalRecords = 0;
			return new MembershipUserCollection();
		}

		#endregion

		#region Validation

		protected virtual string ValidateUserName(string userName)
		{
			if (string.IsNullOrEmpty(userName))
			{
				return null;
			}

			var user = userName.Trim();

			if (string.IsNullOrEmpty(user) || this.InvalidUsernameCharacters.Any(user.Contains) || user.Length > MaxUsernameLength)
			{
				return null;
			}

			return user;
		}

		protected virtual string ValidateEmail(string email)
		{
			if (string.IsNullOrEmpty(email))
			{
				return null;
			}

			var mail = email.Trim();

			if (string.IsNullOrEmpty(email) || this.InvalidEmailCharacters.Any(email.Contains) || email.Length > MaxEmailLength)
			{
				return null;
			}

			return mail;
		}

		protected virtual string ValidatePassword(string password)
		{
			if (string.IsNullOrEmpty(password) || string.IsNullOrWhiteSpace(password) || password.Length > MaxPasswordLength || password.Length < this.MinRequiredPasswordLength)
			{
				return null;
			}

			if (!string.IsNullOrEmpty(this.PasswordStrengthRegularExpression) && !Regex.IsMatch(password, this.PasswordStrengthRegularExpression))
			{
				return null;
			}

			if (this.MinRequiredNonAlphanumericCharacters > 0)
			{
				int numNonAlphaNumericChars = password.Where((t, i) => !char.IsLetterOrDigit(password, i)).Count();

				if (numNonAlphaNumericChars < this.MinRequiredNonAlphanumericCharacters)
				{
					return null;
				}
			}

			return password;
		}

		protected virtual string ValidateQuestion(string question)
		{
			if (!this.RequiresQuestionAndAnswer)
			{
				return string.Empty;
			}

			if (string.IsNullOrEmpty(question))
			{
				return null;
			}

			var questionTrimmed = question.Trim();

			if (string.IsNullOrEmpty(questionTrimmed) || questionTrimmed.Length > MaxPasswordQuestionLength)
			{
				return null;
			}

			return questionTrimmed;
		}

		protected virtual string ValidateAnswer(string answer)
		{
			if (!this.RequiresQuestionAndAnswer)
			{
				return string.Empty;
			}

			if (string.IsNullOrEmpty(answer))
			{
				return null;
			}

			var answerTrimmed = answer.Trim();

			if (string.IsNullOrEmpty(answerTrimmed) || answerTrimmed.Length > MaxPasswordAnswerLength)
			{
				return null;
			}

			return answerTrimmed;
		}

		#endregion

		protected virtual void HandleExceptionAndThrow<T>(T exception) where T : Exception
		{
			if (this.WriteExceptionsToEventLog)
			{
				var log = new EventLog { Source = this.GetType().Name, Log = "Application" };
				var message = string.Format("An exception occurred communicating with the data source.\r\n Exception: {0}", exception);
				log.WriteEntry(message);
			}

			throw exception;
		}
	}
}