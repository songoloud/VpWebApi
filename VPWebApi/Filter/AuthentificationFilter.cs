using AwsAuthentification.Signers;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Http.Filters;
using System.Web.Http.Results;

namespace VPWebApi.Filter
{
    public class AuthentificationFilter : Attribute, IAuthenticationFilter
    {
        //static readonly string AWSAccessKey = ConfigurationManager.AppSettings["AWSAccessKey"];
        static readonly string AWSSecretKey = ConfigurationManager.AppSettings["AWSSecretKey"];

        public bool AllowMultiple => throw new NotImplementedException();

        public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            var req = context.Request;
            var auth = req.Headers.Authorization;
            var authorizationheader = req.Headers.FirstOrDefault(a => a.Key.Equals("Authorization"));
            if (authorizationheader.Value != null)
            {
                var rawAuthzHeader = authorizationheader.Value.FirstOrDefault();
                if (rawAuthzHeader.StartsWith("AWS "))
                {
                    var authroize = rawAuthzHeader.Substring(4);
                    var signaturearray = authroize.Split(':');

                    var awsAccessKey = signaturearray[0];
                    var canonicalizedHeaderNames = signaturearray[1];
                    var signatureStringtoSign = signaturearray[2];

                    
                    var canonicalizedHeaders = CanonicalizeHeaders(req);

                    // if any query string parameters have been supplied, canonicalize them
                    // (note this sample assumes any required url encoding has been done already)
                    var canonicalizedQueryParameters = string.Empty;


                    // canonicalize the various components of the request
                    var canonicalRequest = CanonicalizeRequest(req.RequestUri,//EndpointUri,
                                                               req.Method.Method,// HttpMethod,
                                                               canonicalizedQueryParameters,
                                                               canonicalizedHeaderNames,
                                                               canonicalizedHeaders,
                                                               AWS4SignerBase.EMPTY_BODY_SHA256);
                                                               
                    Console.WriteLine("\nCanonicalRequest:\n{0}", canonicalRequest);


                    var requestDateTime = DateTime.ParseExact(req.Headers.FirstOrDefault(a => a.Key.Equals("X-Amz-Date")).Value.FirstOrDefault(), "yyyyMMddTHHmmssZ", CultureInfo.InvariantCulture);
                    
                    var dateTimeStamp = requestDateTime.ToString("yyyyMMddTHHmmssZ", CultureInfo.InvariantCulture);

                    var dateStamp = requestDateTime.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
                 

          
                    var kDate = Encode("AWS" + AWSSecretKey, dateStamp);
                    var kRegion = Encode(kDate, "");
                    var kService = Encode(kRegion, "");
                    var kcanonicalRequest = Encode(kService, canonicalRequest);
                    var stringToSign = Encode(kcanonicalRequest, "aws4_request");
                    
                    System.Diagnostics.Debug.WriteLine(stringToSign);
                    var signatureString = stringToSign; 
                   

                    if (signatureString.Equals(signatureStringtoSign))
                    {
                        var currentPrincipal = new GenericPrincipal(new GenericIdentity(awsAccessKey), null);
                        context.Principal = currentPrincipal;
                    }
                    else
                    {
                        context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0], context.Request);
                    }
                }
               
            }
            else
            {
                context.ErrorResult = new UnauthorizedResult(new AuthenticationHeaderValue[0], context.Request);
            }

            return Task.FromResult(0);
        }
  

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            context.Result = new ResultWithChallenge(context.Result);
            return Task.FromResult(0);
        }

        private string Encode(string message, string secret)
        {
            secret = secret ?? "";
            var encoding = new System.Text.ASCIIEncoding();
            byte[] keyByte = encoding.GetBytes(secret);
            byte[] messageBytes = encoding.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
                return Convert.ToBase64String(hashmessage);
            }
        }


        public class ResultWithChallenge : IHttpActionResult
        {
            private readonly string authenticationScheme = "AWS";
            private readonly IHttpActionResult next;

            public ResultWithChallenge(IHttpActionResult next)
            {
                this.next = next;
            }

            public async Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
            {
                var response = await next.ExecuteAsync(cancellationToken);

                if (response.StatusCode == HttpStatusCode.Unauthorized)
                {
                    response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue(authenticationScheme));
                }

                return response;
            }
        }

        protected string CanonicalizeRequest(Uri endpointUri,
                                             string httpMethod,
                                             string queryParameters,
                                             string canonicalizedHeaderNames,
                                             string canonicalizedHeaders,
                                             string bodyHash)
        {
            var canonicalRequest = new StringBuilder();

            canonicalRequest.AppendFormat("{0}\n", httpMethod);
            canonicalRequest.AppendFormat("{0}\n", CanonicalResourcePath(endpointUri));
            canonicalRequest.AppendFormat("{0}\n", queryParameters);

            canonicalRequest.AppendFormat("{0}\n", canonicalizedHeaders);
            canonicalRequest.AppendFormat("{0}\n", canonicalizedHeaderNames);

            canonicalRequest.Append(bodyHash);

            return canonicalRequest.ToString();
        }
        protected string CanonicalResourcePath(Uri endpointUri)
        {
            if (string.IsNullOrEmpty(endpointUri.AbsolutePath))
                return "/";

            // encode the path per RFC3986
            return UrlEncode(endpointUri.AbsolutePath, true);
        }

        public static string UrlEncode(string data, bool isPath = false)
        {
            // The Set of accepted and valid Url characters per RFC3986. Characters outside of this set will be encoded.
            const string validUrlCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

            var encoded = new StringBuilder(data.Length * 2);
            string unreservedChars = String.Concat(validUrlCharacters, (isPath ? "/:" : ""));

            foreach (char symbol in System.Text.Encoding.UTF8.GetBytes(data))
            {
                if (unreservedChars.IndexOf(symbol) != -1)
                    encoded.Append(symbol);
                else
                    encoded.Append("%").Append(String.Format("{0:X2}", (int)symbol));
            }

            return encoded.ToString();
        }
        private string CanonicalizeHeaders(HttpRequestMessage req)
        {
            //var headers = req.Headers.ToDictionary(p=>p.Key);
            Dictionary<string, string> headers = new Dictionary<string, string>();

            var listh = req.Headers.Where(h => h.Key != null);
            foreach (var h in listh)
            {
                if (h.Key.ToLower().Equals("authorization") || h.Key.ToLower().Equals("connection") || h.Key.ToLower().Equals("expect"))
                    continue;
                headers.Add(h.Key, h.Value.FirstOrDefault());
            }

            if (headers == null || headers.Count == 0)
                return string.Empty;

            // step1: sort the headers into lower-case format; we create a new
            // map to ensure we can do a subsequent key lookup using a lower-case
            // key regardless of how 'headers' was created.
            var sortedHeaderMap = new SortedDictionary<string, string>();
            foreach (var header in headers.Keys)
            {
                sortedHeaderMap.Add(header.ToLower(), headers.FirstOrDefault(k=>k.Key == header).Value.ToString());
            }
            sortedHeaderMap.Add("content-type", req.Content.Headers.ContentType.MediaType);
            sortedHeaderMap.Add("content-length", req.Content.Headers.ContentLength.Value.ToString());
            
            // step2: form the canonical header:value entries in sorted order. 
            // Multiple white spaces in the values should be compressed to a single 
            // space.
            var sb = new StringBuilder();
            foreach (var header in sortedHeaderMap.Keys)
            {
                var headerValue = AWS4SignerBase.CompressWhitespaceRegex.Replace(sortedHeaderMap[header], " ");
                sb.AppendFormat("{0}:{1}\n", header, headerValue.Trim());
            }

            return sb.ToString();
        }
        
    }
}