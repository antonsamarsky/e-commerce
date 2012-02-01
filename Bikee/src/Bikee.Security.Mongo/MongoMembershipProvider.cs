﻿using System;
using System.Collections.Specialized;
using System.Configuration.Provider;
using System.Linq;
using System.Web.Security;
using Bikee.Security.Domain;
using FluentMongo.Linq;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Options;
using MongoDB.Driver;
using MongoDB.Driver.Builders;

namespace Bikee.Security.Mongo
{
	public class MongoMembershipProvider : MembershipProviderBase
	{
		private const int NewPasswordLength = 8;

		private string usersCollectionName;
		
		public string CollectionName { get; set; }

		public MongoCollection<User> UsersCollection { get; set; }

		public MongoDatabase Database { get; set; }

		public override void Initialize(string name, NameValueCollection config)
		{
			base.Initialize(name, config);

			// MongoDB specific setting
			this.usersCollectionName = Utils.GetConfigValue(config["usersCollectionName"], "users");

			this.RegisterMapping();
			this.InitDatabse();
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

			var createDate = DateTime.UtcNow;
			var user = new User
			{
				Id = providerUserKey,
				UserName = username.Trim(),
				LowercaseUsername = username.Trim().ToLowerInvariant(),
				DisplayName = username.Trim(),
				Email = email.Trim(),
				LowercaseEmail = email.Trim().ToLowerInvariant(),
				Password = password.Encode(this.PasswordFormat),
				PasswordQuestion = passwordQuestion.Trim(),
				PasswordAnswer = passwordAnswer.Trim().Encode(this.PasswordFormat),
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
			return this.GetUser(providerUserKey, false);
		}

		public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
		{
			if (!base.ChangePasswordQuestionAndAnswer(username, password, newPasswordQuestion, newPasswordAnswer))
			{
				return false;
			}

			var user = this.GetUserByName(username.Trim());
			user.PasswordQuestion = newPasswordQuestion.Trim();
			user.PasswordAnswer = newPasswordAnswer.Trim().Encode(user.PasswordFormat);

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

			if (this.RequiresQuestionAndAnswer && !answer.Trim().ComparePassword(user.PasswordAnswer, user.PasswordFormat))
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

			// Save new password
			user.Password = newPassword.Encode(this.PasswordFormat);
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

			if (this.RequiresQuestionAndAnswer && !answer.Trim().ComparePassword(user.PasswordAnswer, user.PasswordFormat))
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

			if (password.Trim().ComparePassword(user.Password, user.PasswordFormat))
			{
				this.UpdateFailurePasswordCount(user, false);
				throw new MembershipPasswordException("Incorrect password answer.");
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

			var user = this.UsersCollection.FindOneById(id);

			// ToDo Save data using find and modify
			user.LastActivityDate = DateTime.UtcNow;

			return this.ToMembershipUser(user);
		}

		public override MembershipUser GetUser(string username, bool userIsOnline)
		{
			base.GetUser(username, userIsOnline);

			var user = this.GetUserByName(username);

			// ToDo Save data using find and modify
			user.LastActivityDate = DateTime.UtcNow;
			return this.ToMembershipUser(user);
		}

		public override string GetUserNameByEmail(string email)
		{
			base.GetUserNameByEmail(email);

			var user = this.GetUserByMail(email);
			// ToDo Save data using find and modify
			user.LastActivityDate = DateTime.UtcNow;
			return user.UserName;
		}

		public override bool DeleteUser(string username, bool deleteAllRelatedData)
		{
			if (!base.DeleteUser(username, deleteAllRelatedData))
			{
				return false;
			}

			var query = Query.EQ(Utils.GetElementNameFor<User>(u => u.LowercaseUsername), username.ToLowerInvariant());

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

			this.UsersCollection.AsQueryable()
				.Skip(pageIndex * pageSize)
				.Take(pageSize)
				.Select(u => this.ToMembershipUser(u))
				.ToList()
				.ForEach(users.Add);

			return users;
		}

		public override int GetNumberOfUsersOnline()
		{
			// http://msdn.microsoft.com/en-us/library/system.web.security.membership.userisonlinetimewindow.aspx
			TimeSpan onlineSpan = new TimeSpan(0, Membership.UserIsOnlineTimeWindow, 0);
			DateTime compareTime = DateTime.UtcNow.Subtract(onlineSpan);

			return this.UsersCollection.AsQueryable().Count(u => u.LastActivityDate > compareTime);
		}

		public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
		{
			base.FindUsersByName(usernameToMatch, pageIndex, pageSize, out totalRecords);

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

		public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
		{
			base.FindUsersByEmail(emailToMatch, pageIndex, pageSize, out totalRecords);

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

		protected virtual void RegisterMapping()
		{
			new UserBsonMap();
		}

		protected virtual void InitDatabse()
		{
			this.Database = MongoDatabase.Create(this.ConnectionString);
			this.CollectionName = this.usersCollectionName;
			this.UsersCollection = Database.GetCollection<User>(CollectionName);

			DateTimeSerializationOptions.Defaults = DateTimeSerializationOptions.LocalInstance;
		}

		protected virtual User GetUserByMail(string email)
		{
			if (string.IsNullOrEmpty(email))
			{
				this.HandleExceptionAndThrow(new ArgumentNullException("email"));
			}

			return this.UsersCollection.AsQueryable().FirstOrDefault(u => u.LowercaseEmail == email.ToLowerInvariant());
		}

		protected virtual User GetUserByName(string userName)
		{
			if (string.IsNullOrEmpty(userName))
			{
				this.HandleExceptionAndThrow(new ArgumentException("userName"));
			}

			return this.UsersCollection.AsQueryable().FirstOrDefault(u => u.LowercaseUsername == userName.ToLowerInvariant());
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
