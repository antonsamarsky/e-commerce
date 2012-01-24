using System.Web.Mvc;

namespace Bikee.Web.Controllers
{
	public class HomeController : Controller
	{
		public ActionResult Index()
		{
			ViewBag.Message = "Welcome to Bikee portal!";

			return View();
		}

		public ActionResult About()
		{
			return View();
		}
	}
}
