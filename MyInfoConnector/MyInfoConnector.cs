using Jose;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using System.Web;

namespace MyInfoConnector
{
    public class MyInfoConnector
    {
        private MyInfoConnectorConfig _config;
        private ILogger _logger;
        readonly HttpClient client;

        public static MyInfoConnector Create(MyInfoConnectorConfig config, ILogger logger = null)
        {
            return new MyInfoConnector(config, logger);
        }

        private MyInfoConnector(MyInfoConnectorConfig config, ILogger logger = null)
        {           
            _config = config;
            _logger = logger;
            HttpClientHandler httpClientHandler = new HttpClientHandler();
            httpClientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };
            // https://public.cloud.myinfo.gov.sg/myinfo/api/myinfo-kyc-v4.0.html#section/Security/Enhancements-in-v4 support tls1.2
            httpClientHandler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
            client = new HttpClient(httpClientHandler);

            (bool isValid, string[] messages) = CheckConfiguration();
            // valid configuration
            if (!isValid)
            {
                if (_logger != null)
                {
                    _logger.LogError("Error: ", string.Join("\n", messages));
                }
                throw new Exception(string.Join("\n", messages));
            }
        }

        /// <summary>
        /// This method generates the code verifier and code challenge for the PKCE flow.
        /// </summary>
        /// <returns>return in tuple format, Item1 is codeVerifier, Item2 is codeChallenge</returns>
        public (bool isValid, string[] messages) CheckConfiguration() => _config.IsValid();

        public (string, string) GeneratePKCECodePair()
        {
            string codeVerifier = MyInfoSecurityHelper.CreateCodeVerifier();
            string codeChallenge = MyInfoSecurityHelper.CreateCodeChallenge(codeVerifier);
            return (codeVerifier, codeChallenge);
        }

        /// <summary>
        /// 
        /// This method takes in all the required variables, invoke the following APIs.
        /// Get Access Token(Token API) - to get Access Token by using the Auth Code
        /// Get Person Data(Person API) - to get Person Data by using the Access Token
        /// 
        /// </summary>
        /// <param name="authCode">Authorization Code from Authorize API</param>
        /// <param name="codeVerifier">Code verifier that corresponds to the code challenge used to retrieve authcode</param>
        /// <param name="privateSigningKey">Your application private signing key in .pem format</param>
        /// <param name="privateEncryptionKey">Your application private encryption keys in .pem format, pass in a list of private keys that corresponds to JWKS encryption public keys</param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public async Task<string> GetMyInfoPersonJson(string authCode, string codeVerifier, string privateSigningKey, string privateEncryptionKey)
        {
            (bool isValid, string[] messages) = CheckConfiguration();
            // valid configuration
            if (!isValid)
            {
                if (_logger != null)
                {
                    _logger.LogError("Error: ", string.Join("\n", messages));
                }
                throw new Exception(string.Join("\n", messages));
            }
            try
            {
                EphemeralKeyPair sessionEphemeralKeyPair = MyInfoSecurityHelper.GenerateEphemeralKeys();
                //create API call to exchange autcode for access_token
                string accessToken = await GetAccessToken(authCode, privateSigningKey, codeVerifier, sessionEphemeralKeyPair);


                if(_logger != null)
                {
                    _logger.LogInformation("get accesstoken successfully: " + accessToken);
                }


                //create API call to exchange access_token to retrieve user's data
                string personJson = await GetPersonJson(accessToken, sessionEphemeralKeyPair, privateEncryptionKey);

                return personJson;
            }
            catch (Exception e)
            {
                if (_logger != null)
                {
                    _logger.LogError("Error: ", e.ToString());
                }
                throw e;
            }
        }
        /// <summary>
        ///  This method calls the Person API and returns a JSON response with the
        /// personal data that was requested.Your application needs to provide a
        /// valid "access token" in exchange for the JSON data.Once your application
        /// receives this JSON data, you can use this data to populate the online
        /// form on your application.
        /// </summary>
        /// <param name="accessToken">Access token from Token API</param>
        /// <param name="sessionEphemeralKeyPair">Session EphemeralKeyPair used to sign DPoP</param>
        /// <param name="privateEncryptionKey">Your application private encryption keys in .pem format, pass in a list of private keys that corresponds to JWKS encryption public keys</param>
        /// <returns>Returns the Person Data (Payload decrypted + Signature validated)</returns>
        /// <exception cref="Exception"></exception>
        /// 
        protected async Task<string> GetPersonJson(string accessToken, EphemeralKeyPair sessionEphemeralKeyPair, string privateEncryptionKey)
        {
            string decodedAccessToken = MyInfoSecurityHelper.VerifyToken(accessToken, _config.AuthoriseJWKSUrl, client);
            if (string.IsNullOrEmpty(decodedAccessToken))
            {
                if (_logger != null)
                {
                    _logger.LogError("Error: ", "Invalid access token");
                }
                throw new Exception("Invalid access token");
            }

            JObject decodedAccessTokenObject = JsonConvert.DeserializeObject<JObject>(decodedAccessToken);
            string uinFin = (string)decodedAccessTokenObject["sub"];
            if (string.IsNullOrEmpty(uinFin))
            {
                if (_logger != null)
                {
                    _logger.LogError("Error: ", "Uinfin not found");
                }
                throw new Exception("Uinfin not found");
            }

            string encryptedPersonTokenJson = await CallPersonAPI(uinFin, accessToken, sessionEphemeralKeyPair);

            if (string.IsNullOrEmpty(encryptedPersonTokenJson))
            {
                if (_logger != null)
                {
                    _logger.LogError("Error: ", "Error on person api call");
                }
                throw new Exception("Error on person api call");
            }
            #region "Decrypt & Verify the Person Response"
            try
            {
                return DecodeTokenToPerson(encryptedPersonTokenJson, privateEncryptionKey);
            }
            catch (Exception ex)
            {
                if (_logger != null)
                {
                    _logger.LogError("Error: ", $"{nameof(GetPersonJson)} failed to decode the encrypted result: {ex.Message}");
                }
                throw new Exception($"{nameof(GetPersonJson)} failed to decode the encrypted result: {ex.Message}");
            }
            #endregion
        }

        protected async Task<string> CallPersonAPI(string uinFin, string accessToken, EphemeralKeyPair sessionEphemeralKeyPair)
        {

            var specificPersonUrl = $"{_config.PersonUrl}/{uinFin}";

            // compute ath
            string ath = Base64Url.Encode(MyInfoSecurityHelper.Sha256(accessToken));
            string tokendPoP = MyInfoSecurityHelper.GenerateDPoP(specificPersonUrl, ApplicationConstant.GET_METHOD, sessionEphemeralKeyPair, ath);

            // Assembling params for Token API
            var paramsDict = new Dictionary<string, string>()
            {
                { ApplicationConstant.SCOPE, _config.Scope},
            };

            string apiUrlWithParams = specificPersonUrl + GetQueryString(paramsDict);
            var request = new HttpRequestMessage(HttpMethod.Get, apiUrlWithParams);
            request.Headers.Clear();
            request.Headers.Add(ApplicationConstant.CACHE_CONTROL, ApplicationConstant.NO_CACHE);
            request.Headers.Add(ApplicationConstant.ACCEPT, "application/json");
            // required headers
            request.Headers.Authorization = new AuthenticationHeaderValue(ApplicationConstant.DPOP, accessToken);
            request.Headers.Add(ApplicationConstant.DPOP, tokendPoP);

            var response = await client.SendAsync(request);
            var responseString = await response.Content.ReadAsStringAsync();
            if (response.StatusCode != HttpStatusCode.OK)
            {
                if(_logger != null)
                {                   
                    _logger.LogError("Error in person api call: ", $"{responseString}");
                }
                throw new Exception("Error in person api call: " + $"{responseString}");

            }
            return responseString;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="authCode">Authorization Code from authorize API</param>
        /// <param name="privateSigningKey">The Client Private Key in JSON format</param>
        /// <param name="codeVerifier">Code verifier that corresponds to the code challenge used to retrieve authcode</param>
        /// <param name="sessionEphemeralKeyPair">Session EphemeralKeyPair used to sign DPoP</param>
        /// <returns></returns>
        protected async Task<string> GetAccessToken(string authCode, string privateSigningKey, string codeVerifier, EphemeralKeyPair sessionEphemeralKeyPair)
        {
            //Creates new DPoP proof
            string tokendPoP = MyInfoSecurityHelper.GenerateDPoP(_config.TokenUrl, ApplicationConstant.POST_METHOD, sessionEphemeralKeyPair, "");

            //Generate Client Assertions
            string jktThumbprint = MyInfoSecurityHelper.GenerateJwkThumbprint(sessionEphemeralKeyPair.PublicKey);
            string clientAssertion = MyInfoSecurityHelper.GenerateClientAssertion(_config.TokenUrl, _config.ClientId, privateSigningKey, jktThumbprint, "");

            // Assembling params for Token API
            var paramsDict = new Dictionary<string, string>()
            {
                { ApplicationConstant.CODE, authCode},
                { ApplicationConstant.GRANT_TYPE, ApplicationConstant.AUTHORIZATION_CODE},
                { ApplicationConstant.CLIENT_ID, _config.ClientId},
                { ApplicationConstant.REDIRECT_URI, _config.RedirectUrl},
                { ApplicationConstant.CLIENT_ASSERTION, clientAssertion},
                { ApplicationConstant.CLIENT_ASSERTION_TYPE, ApplicationConstant.CLIENT_ASSERTION_TYPE_VALUE},
                { ApplicationConstant.CODE_VERIFIER, codeVerifier}
            };

            //  string apiUrlWithParams = QueryHelpers.AddQueryString(_config.TokenUrl, paramsDict);

            //start request 
            var request = new HttpRequestMessage(HttpMethod.Post, _config.TokenUrl);
            request.Headers.Clear();
            request.Headers.Add(ApplicationConstant.CACHE_CONTROL, ApplicationConstant.NO_CACHE);
            request.Headers.Add(ApplicationConstant.ACCEPT, "application/json");
            request.Headers.Add(ApplicationConstant.DPOP, tokendPoP);
            // request body content
            HttpContent body = new FormUrlEncodedContent(paramsDict);
            body.Headers.ContentType = new MediaTypeHeaderValue(ApplicationConstant.CONTENT_TYPE_VALUE);
            request.Content = body;

            var response = await client.SendAsync(request);
            string responseString = await response.Content.ReadAsStringAsync();

            if (response.StatusCode != HttpStatusCode.OK)
            {
                if(_logger != null)
                {
                    _logger.LogError("Error in token api call: ", $"{responseString}");
                }
                throw new Exception("Error in token api call: " + $"{responseString}");
            }

            object jsonObject = JsonConvert.DeserializeObject(responseString);
            var jsonObj = JObject.Parse(jsonObject.ToString());
            string accessToken = (string)jsonObj.SelectToken("access_token");
            return accessToken;
        }

        internal string DecodeTokenToPerson(string encryptedPersonTokenJson, string privateEncryptionKey)
        {
            string decodedJson = string.Empty;
            string plainToken = string.Empty;

            var headers = JWT.Headers(encryptedPersonTokenJson);
            // check jwt token is jwe or jws
            if (headers.ContainsKey("enc"))  // if it's jwe, decrypt first
            {
                // step 1 Decrypt the payload with your application's private key

                try
                {
                    Jwk privateEncryptionJWK = Jwk.FromJson(privateEncryptionKey, JWT.DefaultSettings.JsonMapper);
                    plainToken = JWT.Decode(encryptedPersonTokenJson, privateEncryptionJWK);
                }
                catch
                {
                    plainToken = encryptedPersonTokenJson;
                }
            }
            else
            {
                plainToken = encryptedPersonTokenJson;
            }

            // step 2: Validate the decrypted payload signature with Myinfo public key (JWKS URI) (Reference: JWS)
            string decodedPlayload = MyInfoSecurityHelper.VerifyToken(plainToken, _config.MyInfoJWKSUrl, client);

            if (string.IsNullOrEmpty(decodedPlayload))
            {
                Console.WriteLine($"{nameof(DecodeTokenToPerson)} Failed to verify using MyInfo's public jwks.");
            }

            return decodedPlayload;
        }

        private string GetQueryString(IDictionary<string, string> dict)
        {
            string queryParams = string.Empty;
           // var list = new List<string>();
            foreach (var item in dict)
            {
               queryParams += $"&{Uri.EscapeDataString(item.Key)}={Uri.EscapeDataString(item.Value)}";           
            }
            return "?" + queryParams.Substring(1);
        }
    }
}
