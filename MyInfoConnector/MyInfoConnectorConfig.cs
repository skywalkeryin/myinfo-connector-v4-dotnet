
namespace MyInfoConnector
{
    public class MyInfoConnectorConfig
    {
        /// <summary>
        /// Client id provided during onboarding
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Redirect URL for web application
        /// </summary>
        public string RedirectUrl { get; set; }

        /// <summary>
        /// Space separated list of attributes to be retrieved from Myinfo
        /// </summary>
        public string Scope { get; set; }

        /// <summary>
        /// The URL to retrieve authorize JWKS public key
        /// </summary>
        public string AuthoriseJWKSUrl { get; set; }
        /// <summary>
        /// The URL to retrieve Myinfo JWKS public key
        /// </summary>
        public string MyInfoJWKSUrl { get; set; }


        private string _tokenUrl { get; set; }

        /// <summary>
        /// The URL for Token API
        /// </summary>
        public string TokenUrl {
            get
            {
                return removeLastSlash(_tokenUrl);
            }
            set { _tokenUrl = value; }
        }

        private string _personUrl { get; set; }

        /// <summary>
        /// The URL for Person API
        /// </summary>
        public string PersonUrl
        {
            get
            {
                return removeLastSlash(_personUrl);
            }
            set { _personUrl = value; }
        }

      
        /// <summary>
        /// Sanity check the settings but don't throw
        /// Allow the caller to react appropriately
        /// </summary>
        public (bool isValid, string[] messages) IsValid()
        {
            var messages = new List<string>();

            if (string.IsNullOrEmpty(ClientId)) messages.Add("ClientId missing or empty");
            if (string.IsNullOrEmpty(RedirectUrl)) messages.Add("RedirectUrl missing or empty");
            if (string.IsNullOrEmpty(Scope)) messages.Add("Scope missing or empty");
            if (string.IsNullOrEmpty(AuthoriseJWKSUrl)) messages.Add("AuthoriseJWKSUrl missing or empty");
            if (string.IsNullOrEmpty(MyInfoJWKSUrl)) messages.Add("MyInfoJWKSUrl missing or empty");
            if (string.IsNullOrEmpty(TokenUrl)) messages.Add("TokenUrl missing or empty");
            if (string.IsNullOrEmpty(TokenUrl)) messages.Add("TokenUrl missing or empty");
            if (string.IsNullOrEmpty(PersonUrl)) messages.Add("PersonUrl missing or empty");

            return (messages.Count == 0, messages.ToArray());
        }

        private string removeLastSlash(string url)
        {
            if (url.EndsWith("/"))
            {
                return url.Substring(0, url.Length - 1);
            }
            else
            {
                return url;
            }
        }
    }
}
