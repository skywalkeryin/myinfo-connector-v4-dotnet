using Jose;
using Jose.keys;
using System.Security.Cryptography;
using System.Text;
using static Jose.Jwk;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;


namespace MyInfoConnector
{
    public class EphemeralKeyPair
    {
        public Jwk PrivateKey { get; set; }
        public Jwk PublicKey { get; set; }
    }

    public enum KeyFileFormat { 
        PEM = 0,
        JSON = 1
   }

    public class MyInfoSecurityHelper
    {
        /// <summary>
        /// Create code verifier
        /// </summary>
        /// <returns></returns>
        public static string CreateCodeVerifier()
        {
            string verifier = GenerateSecurityRandomString(32);
            return verifier;
        }

        /// <summary>
        /// Create code verifier
        /// </summary>
        /// <returns></returns>
        public static string CreateCodeChallenge(string verifier)
        {
            try
            {
                byte[] hashValue = Sha256(verifier);
                string challenge = Base64Url.Encode(hashValue);
                return challenge;
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        /// <summary>
        /// This method will generate a keypair which consists of an eliptic curve public key and a private key.
        /// </summary>
        /// <returns></returns>
        public static EphemeralKeyPair GenerateEphemeralKeys()
        {
            EphemeralKeyPair ephemeralKeyPair = new EphemeralKeyPair();
            CngKey receiverPubKey = CngKey.Create(CngAlgorithm.ECDsaP256);
            EccKey eccprivateKey = EccKey.Generate(receiverPubKey);

            ephemeralKeyPair.PrivateKey = new Jwk
            {
                Alg = "ES256",
                Use = KeyUsage.Signature,
                X = Base64Url.Encode(eccprivateKey.X),
                Y = Base64Url.Encode(eccprivateKey.Y),
                D = Base64Url.Encode(eccprivateKey.D),
                Crv = "P-256",
                Kty = KeyTypes.EC
            };

            ephemeralKeyPair.PublicKey = new Jwk
            {
                Alg = "ES256",
                Use = KeyUsage.Signature,
                X = Base64Url.Encode(eccprivateKey.X),
                Y = Base64Url.Encode(eccprivateKey.Y),
                Crv = "P-256",
                Kty = KeyTypes.EC
            };

            return ephemeralKeyPair;
        }
        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        private static long GetEpochDateTimeAsInt(DateTime datetime)
        {
            DateTime dateTime = datetime;
            if (datetime.Kind != DateTimeKind.Utc)
                dateTime = datetime.ToUniversalTime();
            if (dateTime.ToUniversalTime() <= UnixEpoch)
                return 0;
            return (long)(dateTime - UnixEpoch).TotalSeconds;
        }

        /// <summary>
        /// refer to https://api.singpass.gov.sg/library/myinfo/developers/clientassertion
        /// </summary>
        /// <param name="url">The URL of the audience that clientAssertion is for (/token API)</param>
        /// <param name="clientId">Client id provided during onboarding</param>
        /// <param name="privateSigningKey">Your application private signing key in JSON format</param>
        /// <param name="jktThumbprint">JWK Thumbprint - base64url encoding of the JWK SHA-256 Thumbprint of the client's ephemeral public signing key used to sign the DPoP Proof JWT</param>
        /// <param name="kid"> kid that will be used in JWT header</param>
        /// <returns>Returns the client assertion</returns>
        public static string GenerateClientAssertion(string url, string clientId, string privateSigningKey, string jktThumbprint, string kid)
        {
            try
            {
                var now = GetEpochDateTimeAsInt(DateTime.UtcNow);
                var payload = new Dictionary<string, object>(){
                    {"sub", clientId },
                    { "jti",  GenerateSecurityRandomString(40)},
                    { "aud", url },
                    { "iss", clientId },
                    { "iat", now},
                    { "exp", now + 300}, // expriy in 5 minutes
                    { "cnf", new { jkt = jktThumbprint } }
                };

                var privateKey = Jwk.FromJson(privateSigningKey, JWT.DefaultSettings.JsonMapper);

                var extraHeaders = new Dictionary<string, object>()
                {
                    { "typ", "JWT" },
                    { "alg", "ES256" },
                };

                if (!string.IsNullOrEmpty(kid))
                {
                    extraHeaders.Add("kid", "kid");
                }

                string token = JWT.Encode(payload, privateKey, JwsAlgorithm.ES256, extraHeaders);
                return token;
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        /// <summary>
        /// refer to 
        /// </summary>
        /// <param name="url">The URL of the audience that DPoP is for (/token API or /person API)</param>
        /// <param name="method">The HTTP method used - e.g ('POST' for /token, 'GET' for /person)</param>
        /// <param name="sessionPopKeyPair">Session ephemeral key pair used for signing DPoP</param>
        /// <param name="ath">Access token hash (Payload) - The base64url encoded SHA-256 hash of the ASCII encoding of the associated access token's value (Required only for /person call after DPoP-bound access token is issued)</param>
        /// <returns>Returns the DPoP Token</returns>
        public static string GenerateDPoP(string url, string method, EphemeralKeyPair sessionPopKeyPair, string ath)
        {
            try
            {
                var now = GetEpochDateTimeAsInt(DateTime.UtcNow);
                var payload = new Dictionary<string, object>(){
                    { "htu", url },
                    { "htm", method },
                    { "jti",  GenerateSecurityRandomString(40)},
                    { "iat", now},
                    { "exp", now + 120} // expriy in 2 minutes
                };
                if (!string.IsNullOrEmpty(ath))
                {
                    payload.TryAdd("ath", ath);
                }

                var extraHeaders = new Dictionary<string, object>()
                {
                    { "typ", "dpop+jwt" },
                    {
                        "jwk", new
                        {
                            kty = sessionPopKeyPair.PublicKey.Kty,
                            kid = sessionPopKeyPair.PublicKey.KeyId,
                            crv = sessionPopKeyPair.PublicKey.Crv,
                            x = sessionPopKeyPair.PublicKey.X,
                            y = sessionPopKeyPair.PublicKey.Y,
                            use = sessionPopKeyPair.PublicKey.Use,
                            alg = sessionPopKeyPair.PublicKey.Alg
                        }
                    },
                    { "alg", "ES256" }
                };

                string token = JWT.Encode(payload, sessionPopKeyPair.PrivateKey, JwsAlgorithm.ES256, extraHeaders);
                return token;
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        private static string GenerateSecurityRandomString(int length)
        {
            byte[] code = new byte[length];
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(code);
            }

            string randomString = Base64Url.Encode(code);
            return randomString;
        }

        /// <summary>
        /// refert to https://stackoverflow.com/a/42590106
        /// </summary>
        /// <param name="jwk"></param>
        /// <returns></returns>
        public static string GenerateJwkThumbprint(Jwk jwk)
        {
            // sort the property
            string sortedKeyJson = "";
            if (jwk.Kty == KeyTypes.EC)
            {
                var sortedKey = new
                {
                    crv = jwk.Crv,
                    kty = jwk.Kty,
                    x = jwk.X,
                    y = jwk.Y,
                };
                sortedKeyJson = JsonConvert.SerializeObject(sortedKey);
            }

            byte[] hash = Sha256(sortedKeyJson);
            string thumbPrint = Base64Url.Encode(hash);
            return thumbPrint;
        }

        public static string VerifyToken(string token, string jwksUrl, HttpClient httpClient)
        {
            try
            {
                #region " Grab public keys from partner endpoint"
                var response = httpClient.GetAsync(jwksUrl).Result;
                var responseString = response.Content.ReadAsStringAsync().Result;
                JwkSet jwks = JwkSet.FromJson(responseString, JWT.DefaultSettings.JsonMapper);
                #endregion

                #region "Get hint from token headers"
                var headers = JWT.Headers(token);
                #endregion

                // find the public sign key based on the key id in jwt token header
                Jwk matchedPubKey = jwks.FirstOrDefault(x => x.KeyId == (string)headers["kid"]);

                // verify the token signature using the public key
                string payload = JWT.Decode(token, matchedPubKey);
                return payload;
            }
            catch (Exception e)
            {
                throw e;
            }
        }
        public static byte[] Sha256(string chars)
        {
            using SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(chars));
            return hash;
        }

        /// <summary>
        /// refert to https://www.scottbrady91.com/c-sharp/pem-loading-in-dotnet-core-and-dotnet
        /// get content from pem or json private key file, then convert to json string
        /// </summary>
        /// <param name="privateFilePath"></param>
        /// <returns></returns>
        public static string GetJsonFromKeyFile(string privateFilePath)
        {
            var privateFileContent = File.ReadAllText(privateFilePath);
            string privateKeyJson = "";
            if (privateFilePath.EndsWith(".pem"))
            {
                Jwk jwk = GetKeyFromKeyFile(privateFileContent, KeyFileFormat.PEM);
                privateKeyJson = jwk.ToJson(JWT.DefaultSettings.JsonMapper);
            }
            else if (privateFilePath.EndsWith(".json"))
            {
                privateKeyJson = privateFileContent;
            }

            try
            {
                JObject.Parse(privateKeyJson);
                return privateKeyJson;
            }
            catch (Exception e) { throw e; }
        }

        /// <summary>
        /// refert to https://www.scottbrady91.com/c-sharp/pem-loading-in-dotnet-core-and-dotnet
        /// get content from pem or json private key file, then convert to json string
        /// </summary>
        /// <param name="privateFilePath"></param>
        /// <returns></returns>
        public static Jwk GetKeyFromKeyFile(string content, KeyFileFormat keyFileFormat)
        {
            if (keyFileFormat == KeyFileFormat.PEM)
            {
                var key = ECDsa.Create();
                key.ImportFromPem(content);
                Jwk jwk = new Jwk(key, true);
                return jwk;
            }
            else if (keyFileFormat == KeyFileFormat.JSON)
            {
                try
                {
                    JObject.Parse(content);
                    Jwk jwk = Jwk.FromJson(content, JWT.DefaultSettings.JsonMapper);
                    return jwk;
                }
                catch (Exception e) { throw e; }
            }
            return null;
        }
    }
}
