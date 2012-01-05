using System.Web.Mvc;
using Bikee.Web.Controllers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Bikee.Web.Tests.Controllers
{
	[TestClass]
	public class HomeControllerTest
	{
		[TestMethod]
		public void Index()
		{
			// Arrange
			HomeController controller = new HomeController();

			// Act
			ViewResult result = controller.Index() as ViewResult;

			// Assert
			Assert.AreEqual("Welcome to Bikee portal!", result.ViewBag.Message);
		}

		[TestMethod]
		public void About()
		{
			// Arrange
			HomeController controller = new HomeController();

			// Act
			ViewResult result = controller.About() as ViewResult;

			// Assert
			Assert.IsNotNull(result);
		}
	}
}
