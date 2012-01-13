using Bikee.Security.Domain;

namespace Bikee.Security
{
	public class AccountRepository : IAccountRepository
	{
		#region Implementation of IAccountRepository

		public bool IsValidLogin(string username, string password)
		{
			throw new System.NotImplementedException();
		}

		#endregion
	}
}