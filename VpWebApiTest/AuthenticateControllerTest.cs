using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using VPWebApi.Controllers;
using VPWebApi.Models;

namespace VpWebApiTest
{
    [TestClass]
    public class AuthenticateControllerTest
    {

        [TestMethod]
        public void ShouldReturnTrue()
        {           
            var controller = new AuthenticateController();
            var user = new Users() { UserEmail = "User1@vp.com", UserPassword = "123456789" };
            var result = controller.Authenticate(user);
            Assert.AreEqual(true, result);
        }

        [TestMethod]
        public void ShouldReturnTrue1()
        {
            var controller = new AuthenticateController();
            var user = new Users() { UserEmail = "User2@vp.com", UserPassword = "123456789" };
            var result = controller.Authenticate(user);
            Assert.AreEqual(true, result);
        }


        [TestMethod]
        public void ShouldReturnFalse()
        {
            var controller = new AuthenticateController();
            var user = new Users() { UserEmail = "vp@vp.com", UserPassword = "123456789" };
            var result = controller.Authenticate(user);
            Assert.AreEqual(false, result);
        }

        [TestMethod]
        public void ShouldReturnFalse1()
        {
            var controller = new AuthenticateController();
            var user = new Users() { UserEmail = "User1@vp.com", UserPassword = "aze21q" };
            var result = controller.Authenticate(user);
            Assert.AreEqual(false, result);
        }


        [TestMethod]
        public void ShouldReturnFalse3()
        {
            var controller = new AuthenticateController();
            var user = new Users() {  UserPassword = "123456789" };
            var result = controller.Authenticate(user);
            Assert.AreEqual(false, result);
        }

        [TestMethod]
        public void ShouldReturnFalse4()
        {
            var controller = new AuthenticateController();
            var user = new Users() { UserEmail = "User1@vp.com" };
            var result = controller.Authenticate(user);
            Assert.AreEqual(false, result);
        }
    }
}
