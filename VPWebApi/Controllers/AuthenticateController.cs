using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using VPWebApi.Models;

namespace VPWebApi.Controllers
{

    [RoutePrefix("api/Authenticate")]
    public class AuthenticateController : ApiController
    {
        [Route("")]
        [HttpPost]
        public bool Authenticate([FromBody]Users users)
        {
            if (users == null)
                return false;

            if (string.IsNullOrEmpty(users.UserEmail) || string.IsNullOrEmpty(users.UserPassword))
                return false;

            var user = Users.ListUsers().FirstOrDefault(u => u.UserEmail.Equals(users.UserEmail) && u.UserPassword.Equals(users.UserPassword));
            if(user != null)
                return true;

            return false;

        }
     
    }
}
