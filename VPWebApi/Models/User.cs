using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace VPWebApi.Models
{    public class Users
    {
        public int UserID { get; set; }
        public string UserName { get; set; }
        [JsonProperty("UserEmail")]
        public string UserEmail { get; set; }
        [JsonProperty("UserPassword")]
        public string UserPassword { get; set; }


        public static List<Users> ListUsers()
        {
            List<Users> OrderList = new List<Users>
            {
                new Users {UserID = 10248, UserName = "User1", UserEmail = "User1@vp.com", UserPassword = "123456789" },
                new Users {UserID = 10249, UserName = "User2", UserEmail = "User2@vp.com", UserPassword = "123456789"},
                new Users {UserID = 10250,UserName = "User3", UserEmail = "User3@vp.com", UserPassword = "123456789" },
                new Users {UserID = 10251,UserName = "User4", UserEmail = "User4@vp.com", UserPassword = "123456789"},
                new Users {UserID = 10252,UserName = "User5", UserEmail = "User5@vp.com", UserPassword = "123456789"}
            };

            return OrderList;
        }
    }
}