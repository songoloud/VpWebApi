using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using VPWebApi.Filter;
using VPWebApi.Models;

namespace VPWebApi.Controllers
{
    [AuthentificationFilter]
    [RoutePrefix("api/Confidentials")]
    public class ConfidentialsController : ApiController
    {
        [Route("")]
        [HttpPost]
        public bool Authenticate(string email)
        {

            if (string.IsNullOrEmpty(email) )
                return false;

            var user = Users.ListUsers().FirstOrDefault(u => u.UserEmail.Equals(email));
            if (user != null)
                return true;

            return false;

        }

    }

}

