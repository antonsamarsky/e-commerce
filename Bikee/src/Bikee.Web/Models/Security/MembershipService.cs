using System;
using System.Web.Security;

namespace Bikee.Web.Models.Security
{
	public class MembershipService : IMembershipService
	{
		private readonly MembershipProvider _provider;

		public MembershipService() : this(null)
		{
		}

		public MembershipService(MembershipProvider provider)
		{
			_provider = provider ?? Membership.Provider;
		}

		public int MinPasswordLength
		{
			get
			{
				return _provider.MinRequiredPasswordLength;
			}
		}

		public bool ValidateUser(string userName, string password)
		{
			if (string.IsNullOrEmpty(userName)) throw new ArgumentException("Value cannot be null or empty.", "userName");
			if (string.IsNullOrEmpty(password)) throw new ArgumentException("Value cannot be null or empty.", "password");

			return _provider.ValidateUser(userName, password);
		}

		public MembershipCreateStatus CreateUser(string userName, string password, string email)
		{
			if (string.IsNullOrEmpty(userName)) throw new ArgumentException("Value cannot be null or empty.", "userName");
			if (string.IsNullOrEmpty(password)) throw new ArgumentException("Value cannot be null or empty.", "password");
			if (string.IsNullOrEmpty(email)) throw new ArgumentException("Value cannot be null or empty.", "email");

			MembershipCreateStatus status;
			_provider.CreateUser(userName, password, email, null, null, true, null, out status);
			return status;
		}

		public bool ChangePassword(string userName, string oldPassword, string newPassword)
		{
			if (string.IsNullOrEmpty(userName)) throw new ArgumentException("Value cannot be null or empty.", "userName");
			if (string.IsNullOrEmpty(oldPassword)) throw new ArgumentException("Value cannot be null or empty.", "oldPassword");
			if (string.IsNullOrEmpty(newPassword)) throw new ArgumentException("Value cannot be null or empty.", "newPassword");

			// The underlying ChangePassword() will throw an exception rather
			// than return false in certain failure scenarios.
			try
			{
				MembershipUser currentUser = _provider.GetUser(userName, true /* userIsOnline */);
				return currentUser != null && currentUser.ChangePassword(oldPassword, newPassword);
			}
			catch (ArgumentException)
			{
				return false;
			}
			catch (MembershipPasswordException)
			{
				return false;
			}
		}
	}
}
