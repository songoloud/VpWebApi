using AwsAuthentification.Signers;
using AwsAuthentification.Util;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace VentePriveTestAuthentification
{
    class ClientRequest
    {
        static readonly string AWSAccessKey = ConfigurationManager.AppSettings["AWSAccessKey"];
        static readonly string AWSSecretKey = ConfigurationManager.AppSettings["AWSSecretKey"];


        

        public ClientRequest(string objectKey, string email)
        {
            objectKey += "?email="+ email;

            var endpointUri = string.Format("http://localhost:59982/{0}", objectKey);

            var uri = new Uri(endpointUri);

           
            //construct the header
            var headers = new Dictionary<string, string>
            {
                {AWS4SignerBase.X_Amz_Content_SHA256, AWS4SignerBase.EMPTY_BODY_SHA256},
                {"content-length", email.Length.ToString()},
                {"content-type", "text/plain"}
            };

            var signer = new AWS4SignerForAuthorizationHeader 
            {
                EndpointUri = uri,
                HttpMethod = "POST",
                Service = "",
                Region =""
            };

            var authorization = signer.ComputeSignature(headers,
                                                        "",   // no query parameters
                                                        AWS4SignerBase.EMPTY_BODY_SHA256,
                                                        AWSAccessKey,
                                                        AWSSecretKey);

            // place the computed signature into a formatted 'Authorization' header 
            // and call S3
            headers.Add("Authorization", authorization);

            HttpHelpers.InvokeHttpRequest(uri, "POST", headers, email);
        }
    }
}
