using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace VentePriveTestAuthentification
{
    class Program
    {               
        private static string objectKey = "api/confidentials";
        static void Main(string[] args)
        {
            new ClientRequest(objectKey, "User1@vp.com");
            new ClientRequest(objectKey, "vpvp@vp.com");
        }
        
        

      
    }
}
