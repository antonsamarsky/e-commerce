namespace Bikee.Security.Domain
{
	public interface IAccountRepository
	{
		bool IsValidLogin(string username, string password);
	}
}