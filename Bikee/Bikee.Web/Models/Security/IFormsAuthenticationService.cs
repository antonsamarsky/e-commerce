namespace Bikee.Web.Models.AccountModel
{
	public interface IFormsAuthenticationService
	{
		void SignIn(string userName, bool createPersistentCookie);
		void SignOut();
	}
}
