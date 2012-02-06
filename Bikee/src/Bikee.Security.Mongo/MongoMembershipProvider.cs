using System;
using System.Collections.Specialized;
using System.Configuration.Provider;
using System.Web.Security;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Options;
using MongoDB.Driver;
using MongoDB.Driver.Builders;

namespace Bikee.Security.Mongo
{
	public class MongoMembershipProvider : MembershipProviderBase
	{
		private const int NewPasswordLength = 8;

		public string UsersCollectionName { get; private set; }

		public MongoCollection<User> UsersCollection { get; set; }

		public override void Initialize(string name, NameValueCollection config)
		{
			base.Initialize(name, config);

			// MongoDB specific setting
			this.UsersCollectionName = SecurityHelper.GetConfigValue(config["usersCollectionName"], "users");

			this.RegisterMapping();
			this.InitDatabase();
			this.EnsureIndexes();
		}

		public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
		{
			base.CreateUser(username, password, email, passwordQuestion, passwordAnswer, isApproved, providerUserKey, out status);

			if (status != MembershipCreateStatus.Success)
			{
				return null;
			}

			if (providerUserKey == null)
			{
				providerUserKey = ObjectId.GenerateNewId();
			}

			string salt;
			string saltAnswer = null;
			var createDate = DateTime.UtcNow;
			var user = new User
			{
				Id = providerUserKey,
				UserName = username.Trim(),
				LowercaseUsername = username.Trim().ToLowerInvariant(),
				DisplayName = username.Trim(),
				Email = email.Trim(),
				LowercaseEmail = email.Trim().ToLowerInvariant(),
				Password = password.Encode(out salt, this.PasswordFormat),
				PasswordSalt = salt,
				PasswordQuestion = this.RequiresQuestionAndAnswer ? passwordQuestion.Trim() : null,
				PasswordAnswer = this.RequiresQuestionAndAnswer ? passwordAnswer.Trim().Encode(out saltAnswer, this.PasswordFormat) : null,
				PasswordAnswerSalt = saltAnswer,
				PasswordFormat = this.PasswordFormat,
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
			return this.ToMembershipUser(user);
		}

		public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
		{
			if (!base.ChangePasswordQuestionAndAnswer(username, password, newPasswordQuestion, newPasswordAnswer))
			{
				return false;
			}

			string salt;
			var user = this.GetUserByName(username.Trim());
			user.PasswordQuestion = newPasswordQuestion.Trim();
			user.PasswordAnswer = newPasswordAnswer.Trim().Encode(out salt, user.PasswordFormat);
			user.PasswordAnswerSalt = salt;

			return true;
		}

		public override string GetPassword(string username, string answer)
		{
			base.GetPassword(username, answer);

			var user = this.GetUserByName(username.Trim());
			if (user == null)
			{
				throw new MembershipPasswordException("The supplied user name is not found.");
			}

			if (user.IsLockedOut)
			{
				throw new MembershipPasswordException("The supplied user is locked out.");
			}

			if (this.RequiresQuestionAndAnswer && !answer.Trim().VerifyPassword(user.PasswordAnswer, user.PasswordFormat, user.PasswordAnswerSalt))
			{
				this.UpdateFailurePasswordAnswerCount(user, false);
				throw new MembershipPasswordException("Incorrect password answer.");
			}

			return user.Password.Decode(user.PasswordFormat);
		}

		public override bool ChangePassword(string username, string oldPassword, string newPassword)
		{
			if (!base.ChangePassword(username, oldPassword, newPassword))
			{
				return false;
			}

			var user = this.GetUserByName(username.Trim());
			if (user == null)
			{
				throw new MembershipPasswordException("The supplied user name is not found.");
			}

			string salt;

			// Save new password
			user.Password = newPassword.Encode(out salt, this.PasswordFormat);
			user.PasswordSalt = salt;
			user.PasswordFormat = this.PasswordFormat;
			user.LastPasswordChangedDate = DateTime.UtcNow;
			this.Save(user);

			return true;
		}

		public override string ResetPassword(string username, string answer)
		{
			base.ResetPassword(username, answer);

			var user = this.GetUserByName(username);
			if (user == null)
			{
				throw new ProviderException("User was not found.");
			}
			if (user.IsLockedOut)
			{
				throw new ProviderException(string.Format("User is locked out. user id: {0}", user.Id));
			}

			if (this.RequiresQuestionAndAnswer && !answer.Trim().VerifyPassword(user.PasswordAnswer, user.PasswordFormat, user.PasswordAnswerSalt))
			{
				this.UpdateFailurePasswordAnswerCount(user, false);
				throw new MembershipPasswordException("Incorrect password answer.");
			}

			string newGeneratedPassword = Membership.GeneratePassword(NewPasswordLength, this.MinRequiredNonAlphanumericCharacters);

			// Raise event to let others check new username/password
			var args = new ValidatePasswordEventArgs(username, newGeneratedPassword, false);
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
			this.Save(user);

			return newGeneratedPassword;
		}

		public override void UpdateUser(MembershipUser user)
		{
			var userFromDB = this.GetUserByName(user.UserName);
			if (userFromDB == null)
			{
				throw new ProviderException("User was not found.");
			}

			userFromDB.UserName = user.UserName;
			userFromDB.Email = user.Email;
			userFromDB.Comment = user.Comment;
			userFromDB.IsApproved = user.IsApproved;
			userFromDB.LastLoginDate = user.LastLoginDate;
			userFromDB.LastActivityDate = user.LastActivityDate;
			this.Save(userFromDB);
		}

		public override bool ValidateUser(string username, string password)
		{
			if (!base.ValidateUser(username, password))
			{
				return false;
			}

			var user = this.GetUserByName(username);
			if (user == null || user.IsLockedOut || !user.IsApproved)
			{
				return false;
			}

			if (!password.VerifyPassword(user.Password, user.PasswordFormat, user.PasswordSalt))
			{
				this.UpdateFailurePasswordCount(user, false);
				throw new MembershipPasswordException("Incorrect password.");
			}

			// User is authenticated. Update last activity and last login dates and failure counts.
			user.LastActivityDate = DateTime.UtcNow;
			user.LastLoginDate = DateTime.UtcNow;
			user.FailedPasswordAnswerAttemptCount = 0;
			user.FailedPasswordAttemptCount = 0;
			user.FailedPasswordAnswerAttemptWindowStart = DateTime.MinValue;
			user.FailedPasswordAttemptWindowStart = DateTime.MinValue;
			this.Save(user);

			return true;
		}

		public override bool UnlockUser(string username)
		{
			if (!base.UnlockUser(username))
			{
				return false;
			}

			User user = this.GetUserByName(username.Trim());
			if (user == null)
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
			this.Save(user);

			return true;
		}

		public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
		{
			base.GetUser(providerUserKey, userIsOnline);

			var id = providerUserKey is BsonValue ? providerUserKey as BsonValue : BsonValue.Create(providerUserKey);

			if (id == null)
			{
				throw new ArgumentException("id");
			}

			var query = Query.EQ(MongoHelper.GetElementNameFor<User>(u => u.Id), id);
			var update = Update.Set(MongoHelper.GetElementNameFor<User, DateTime>(u => u.LastActivityDate), DateTime.UtcNow);

			var result = this.UsersCollection.FindAndModify(query, SortBy.Null, update, true);

			if (!result.Ok)
			{
				this.HandleExceptionAndThrow(new ProviderException(result.ErrorMessage));
			}

			var document = result.ModifiedDocument;
			if (document == null)
			{
				return null;
			}

			var user = BsonSerializer.Deserialize<User>(document);

			return this.ToMembershipUser(user);
		}

		public override MembershipUser GetUser(string username, bool userIsOnline)
		{
			base.GetUser(username, userIsOnline);

			var user = this.GetUserByName(username);

			return this.ToMembershipUser(user);
		}

		public override string GetUserNameByEmail(string email)
		{
			base.GetUserNameByEmail(email);

			var user = this.GetUserByMail(email);
			return user == null ? null : user.UserName;
		}

		public override bool DeleteUser(string username, bool deleteAllRelatedData)
		{
			if (!base.DeleteUser(username, deleteAllRelatedData))
			{
				return false;
			}

			var query = Query.EQ(MongoHelper.GetElementNameFor<User>(u => u.LowercaseUsername), username.ToLowerInvariant());

			var result = this.UsersCollection.Remove(query, SafeMode.True);
			return result.Ok;
		}

		public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
		{
			var users = new MembershipUserCollection();

			// execute second query to get total count
			totalRecords = (int)this.UsersCollection.Count();
			if (totalRecords == 0 || pageIndex <= 0 || pageSize <= 0)
			{
				return users;
			}

			var cursor = this.UsersCollection.FindAll().SetSkip(pageIndex * pageSize).SetLimit(pageSize);

			foreach (var user in cursor)
			{
				users.Add(this.ToMembershipUser(user));
			}

			return users;
		}

		public override int GetNumberOfUsersOnline()
		{
			// http://msdn.microsoft.com/en-us/library/system.web.security.membership.userisonlinetimewindow.aspx
			TimeSpan onlineSpan = new TimeSpan(0, Membership.UserIsOnlineTimeWindow, 0);
			DateTime compareTime = DateTime.UtcNow.Subtract(onlineSpan);

			var query = Query.GT(MongoHelper.GetElementNameFor<User, DateTime>(u => u.LastActivityDate), compareTime);
			return (int)this.UsersCollection.Find(query).Count();
		}

		public override MembershipUserCollection FindUsersByName(string usernamePatternToMatch, int pageIndex, int pageSize, out int totalRecords)
		{
			base.FindUsersByName(usernamePatternToMatch, pageIndex, pageSize, out totalRecords);

			var users = new MembershipUserCollection();

			if (pageIndex < 0 || pageSize < 0)
			{
				totalRecords = 0;
				return users;
			}

			var query = Query.Matches(MongoHelper.GetElementNameFor<User>(u => u.LowercaseUsername), new BsonRegularExpression(usernamePatternToMatch));
			var cursor = this.UsersCollection.Find(query).SetSkip(pageIndex * pageSize).SetLimit(pageSize);

			foreach (var user in cursor)
			{
				users.Add(this.ToMembershipUser(user));
			}

			// Total count;
			totalRecords = (int)this.UsersCollection.Find(query).Count();

			return users;
		}

		public override MembershipUserCollection FindUsersByEmail(string emailPatternToMatch, int pageIndex, int pageSize, out int totalRecords)
		{
			base.FindUsersByEmail(emailPatternToMatch, pageIndex, pageSize, out totalRecords);

			var users = new MembershipUserCollection();

			if (pageIndex < 0 || pageSize < 0)
			{
				totalRecords = 0;
				return users;
			}

			var query = Query.Matches(MongoHelper.GetElementNameFor<User>(u => u.LowercaseEmail), new BsonRegularExpression(emailPatternToMatch));
			var cursor = this.UsersCollection.Find(query).SetSkip(pageIndex * pageSize).SetLimit(pageSize); ;

			foreach (var user in cursor)
			{
				users.Add(this.ToMembershipUser(user));
			}

			// Total count;
			totalRecords = (int)this.UsersCollection.Find(query).Count();

			return users;
		}

		protected virtual void RegisterMapping()
		{
			new UserBsonMap();
		}

		protected virtual void InitDatabase()
		{
			var database = MongoDatabase.Create(this.ConnectionString);
			this.UsersCollection = database.GetCollection<User>(this.UsersCollectionName);

			DateTimeSerializationOptions.Defaults = DateTimeSerializationOptions.LocalInstance;
		}

		protected virtual void EnsureIndexes()
		{
			this.UsersCollection.EnsureIndex(MongoHelper.GetElementNameFor<User>(u => u.LowercaseUsername));
			this.UsersCollection.EnsureIndex(MongoHelper.GetElementNameFor<User>(u => u.LowercaseEmail));
		}

		protected virtual User GetUserByMail(string email)
		{
			if (string.IsNullOrEmpty(email))
			{
				this.HandleExceptionAndThrow(new ArgumentNullException("email"));
				return null;
			}

			var query = Query.EQ(MongoHelper.GetElementNameFor<User>(u => u.LowercaseEmail), email.ToLowerInvariant());
			var update = Update.Set(MongoHelper.GetElementNameFor<User, DateTime>(u => u.LastActivityDate), DateTime.UtcNow);

			var result = this.UsersCollection.FindAndModify(query, SortBy.Null, update, true);

			if (!result.Ok)
			{
				this.HandleExceptionAndThrow(new ProviderException(result.ErrorMessage));
			}

			var document = result.ModifiedDocument;
			return document == null ? null : BsonSerializer.Deserialize<User>(document);
		}

		protected virtual User GetUserByName(string userName)
		{
			if (string.IsNullOrEmpty(userName))
			{
				this.HandleExceptionAndThrow(new ArgumentException("userName"));
				return null;
			}

			var query = Query.EQ(MongoHelper.GetElementNameFor<User>(u => u.LowercaseUsername), userName.ToLowerInvariant());
			var update = Update.Set(MongoHelper.GetElementNameFor<User, DateTime>(u => u.LastActivityDate), DateTime.UtcNow);

			var result = this.UsersCollection.FindAndModify(query, SortBy.Null, update, true);

			if (!result.Ok)
			{
				this.HandleExceptionAndThrow(new ProviderException(result.ErrorMessage));
			}

			var document = result.ModifiedDocument;
			return document == null ? null : BsonSerializer.Deserialize<User>(document);
		}

		protected virtual void Save<T>(T user) where T : User
		{
			SafeModeResult result = null;
			try
			{
				var users = this.UsersCollection;
				result = users.Save(user, SafeMode.True);
			}
			catch (Exception exception)
			{
				this.HandleExceptionAndThrow(exception);
			}

			if (result == null)
			{
				this.HandleExceptionAndThrow(new ProviderException("Save to database did not return a status result"));
			}
			else if (!result.Ok)
			{
				this.HandleExceptionAndThrow(new ProviderException(result.LastErrorMessage));
			}
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

		protected virtual void UpdateFailurePasswordCount(User user, bool isAuthenticated)
		{
			if (user == null || user.IsLockedOut)
			{
				return;
			}

			if (isAuthenticated && user.FailedPasswordAttemptCount > 0)
			{
				user.FailedPasswordAttemptCount = 0;
				user.FailedPasswordAttemptWindowStart = DateTime.UtcNow;
				this.Save(user);
				return;
			}

			var windowStart = user.FailedPasswordAttemptWindowStart;
			var windowEnd = windowStart.AddMinutes(this.PasswordAttemptWindow);
			var failureCount = user.FailedPasswordAttemptCount;

			if (failureCount == 0 || DateTime.UtcNow > windowEnd)
			{
				user.FailedPasswordAttemptCount = 1;
				user.FailedPasswordAttemptWindowStart = DateTime.UtcNow;
				this.Save(user);
				return;
			}

			// Password attempts have exceeded the failure threshold. Lock out the user.
			if (++failureCount >= this.MaxInvalidPasswordAttempts)
			{
				user.IsLockedOut = true;
				user.LastLockoutDate = DateTime.UtcNow;
				user.FailedPasswordAttemptCount = failureCount;
				this.Save(user);
				return;
			}

			// Password attempts have not exceeded the failure threshold. Update the failure counts. Leave the window the same.
			user.FailedPasswordAttemptCount = failureCount;
			this.Save(user);
		}

		protected virtual void UpdateFailurePasswordAnswerCount(User user, bool isAuthenticated)
		{
			if (user == null || user.IsLockedOut)
			{
				return;
			}

			if (isAuthenticated && user.FailedPasswordAnswerAttemptCount > 0)
			{
				user.FailedPasswordAnswerAttemptCount = 0;
				user.FailedPasswordAnswerAttemptWindowStart = DateTime.UtcNow;
				this.Save(user);
				return;
			}

			var windowStart = user.FailedPasswordAnswerAttemptWindowStart;
			var windowEnd = windowStart.AddMinutes(this.PasswordAttemptWindow);
			var failureCount = user.FailedPasswordAnswerAttemptCount;

			if (failureCount == 0 || DateTime.UtcNow > windowEnd)
			{
				user.FailedPasswordAnswerAttemptCount = 1;
				user.FailedPasswordAnswerAttemptWindowStart = DateTime.UtcNow;
				this.Save(user);
				return;
			}

			// Password attempts have exceeded the failure threshold. Lock out the user.
			if (++failureCount >= this.MaxInvalidPasswordAttempts)
			{
				user.IsLockedOut = true;
				user.LastLockoutDate = DateTime.UtcNow;
				user.FailedPasswordAnswerAttemptCount = failureCount;
				this.Save(user);
				return;
			}

			// Password attempts have not exceeded the failure threshold. Update the failure counts. Leave the window the same.
			user.FailedPasswordAnswerAttemptCount = failureCount;
			this.Save(user);
		}
	}
}
