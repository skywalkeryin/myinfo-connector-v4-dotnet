using Jose;
using Jose.keys;
using System.Security.Cryptography;
using System.Text;

namespace MyInfoConnector.Tests
{
    public class MyInfoSecurityHelperFixture
    {


        [Test]
        public void TestCodeChallengeGeneration()
        {
            string codeVerifier = "QVY3aW1OMUJoUzhsZnU3Sm55M05ydkVJZHdRUlhYSVk";
            string codeChallenge = MyInfoSecurityHelper.CreateCodeChallenge(codeVerifier);
            Assert.That(codeChallenge, Is.EqualTo("agyobUjbVK1ZS_wPcLUEBiSl95-UgQqACtLu9byTYQM"));
        }

        [Test]
        public void TestGetKeyFromKeyFile()
        {
            string publicSigningKeyJson = "{\r\n    \"alg\": \"ES256\",\r\n    \"crv\": \"P-256\",\r\n    \"kid\": \"aQPyZ72NM043E4KEioaHWzixt0owV99gC9kRK388WoQ\",\r\n    \"kty\": \"EC\",\r\n    \"use\": \"sig\",\r\n    \"x\": \"BXUWq0Z2RRFqrlWbW2muIybNnj_YBxflNQTEOg-QmCQ\",\r\n    \"y\": \"vXO4G4yDo0iOVJAzmEWyIZwXwnSnGxPIrZe7SX0PKu4\"\r\n}";
            string privateSigningKeyPem = "-----BEGIN EC PRIVATE KEY-----MHcCAQEEIGcOBk0/8HtXAR8XkSinGpVE4GTmbPQnjkhGO+A+QrPaoAoGCCqGSM49AwEHoUQDQgAEBXUWq0Z2RRFqrlWbW2muIybNnj/YBxflNQTEOg+QmCS9c7gbjIOjSI5UkDOYRbIhnBfCdKcbE8itl7tJfQ8q7g==-----END EC PRIVATE KEY-----";

            Jwk publicSigningKey = MyInfoSecurityHelper.GetKeyFromKeyFile(publicSigningKeyJson, KeyFileFormat.JSON);
            Jwk privateSigningKey = MyInfoSecurityHelper.GetKeyFromKeyFile(privateSigningKeyPem, KeyFileFormat.PEM);

            Assert.That(privateSigningKey.X, Is.EqualTo(publicSigningKey.X));
            Assert.That(privateSigningKey.Y, Is.EqualTo(publicSigningKey.Y));

        }


        //refer to https://api.singpass.gov.sg/library/myinfo/developers/dpop-generator
        [Test]
        public void TestDPoP()
        {
            string publicSigningKeyJson = "{\r\n    \"alg\": \"ES256\",\r\n    \"crv\": \"P-256\",\r\n    \"kid\": \"aQPyZ72NM043E4KEioaHWzixt0owV99gC9kRK388WoQ\",\r\n    \"kty\": \"EC\",\r\n    \"use\": \"sig\",\r\n    \"x\": \"BXUWq0Z2RRFqrlWbW2muIybNnj_YBxflNQTEOg-QmCQ\",\r\n    \"y\": \"vXO4G4yDo0iOVJAzmEWyIZwXwnSnGxPIrZe7SX0PKu4\"\r\n}";
            string privateSigningKeyPem = "-----BEGIN EC PRIVATE KEY-----MHcCAQEEIGcOBk0/8HtXAR8XkSinGpVE4GTmbPQnjkhGO+A+QrPaoAoGCCqGSM49AwEHoUQDQgAEBXUWq0Z2RRFqrlWbW2muIybNnj/YBxflNQTEOg+QmCS9c7gbjIOjSI5UkDOYRbIhnBfCdKcbE8itl7tJfQ8q7g==-----END EC PRIVATE KEY-----";
            Jwk publicSigningKey = MyInfoSecurityHelper.GetKeyFromKeyFile(publicSigningKeyJson, KeyFileFormat.JSON);
            Jwk privateSigningKey = MyInfoSecurityHelper.GetKeyFromKeyFile(privateSigningKeyPem, KeyFileFormat.PEM);

            string exceptedDPOP = "eyJ0eXAiOiJkcG9wK2p3dCIsImp3ayI6eyJhbGciOiJFUzI1NiIsImNydiI6IlAtMjU2Iiwia2lkIjoiYVFQeVo3Mk5NMDQzRTRLRWlvYUhXeml4dDBvd1Y5OWdDOWtSSzM4OFdvUSIsImt0eSI6IkVDIiwidXNlIjoic2lnIiwieCI6IkJYVVdxMFoyUlJGcXJsV2JXMm11SXliTm5qX1lCeGZsTlFURU9nLVFtQ1EiLCJ5IjoidlhPNEc0eURvMGlPVkpBem1FV3lJWndYd25Tbkd4UElyWmU3U1gwUEt1NCJ9LCJhbGciOiJFUzI1NiJ9.eyJodHUiOiJodHRwczovL3Rlc3QuYXBpLm15aW5mby5nb3Yuc2cvY29tL3Y0L3Rva2VuIiwiaHRtIjoiUE9TVCIsImp0aSI6ImhxS0VhMEx3bnlPWHRHQlAwOVRvblRCY2t5MEVEcW9MMHFZOGtyQ3EiLCJpYXQiOjE2ODI3NTYwODUsImV4cCI6MTY4Mjc1NjIwNX0.hY1iuKjobNg7Z35stCQYihTOYw6t8FAR3Pf-mk0GEZ_dIpYCY9pZxLd2x5IUfbbeAJKHTxliiTJiHr-EIgld2g";
            EphemeralKeyPair ephemeralKeyPair = new EphemeralKeyPair()
            {
                PrivateKey = privateSigningKey,
                PublicKey = publicSigningKey,
            };

            string print = MyInfoSecurityHelper.GenerateJwkThumbprint(ephemeralKeyPair.PublicKey);
            string token = MyInfoSecurityHelper.GenerateDPoP("https://sit.api.myinfo.gov.sg/com/v4/token", "POST", ephemeralKeyPair, "");
            Assert.IsTrue(exceptedDPOP == token);
        }

        //refer to https://api.singpass.gov.sg/library/myinfo/developers/dpop-generator
        [Test]
        public void TestGenerateJwkThumbprint()
        {
            string publicSigningKeyJson = "{\r\n    \"alg\": \"ES256\",\r\n    \"crv\": \"P-256\",\r\n    \"kid\": \"aQPyZ72NM043E4KEioaHWzixt0owV99gC9kRK388WoQ\",\r\n    \"kty\": \"EC\",\r\n    \"use\": \"sig\",\r\n    \"x\": \"BXUWq0Z2RRFqrlWbW2muIybNnj_YBxflNQTEOg-QmCQ\",\r\n    \"y\": \"vXO4G4yDo0iOVJAzmEWyIZwXwnSnGxPIrZe7SX0PKu4\"\r\n}";
            string privateSigningKeyPem = "-----BEGIN EC PRIVATE KEY-----MHcCAQEEIGcOBk0/8HtXAR8XkSinGpVE4GTmbPQnjkhGO+A+QrPaoAoGCCqGSM49AwEHoUQDQgAEBXUWq0Z2RRFqrlWbW2muIybNnj/YBxflNQTEOg+QmCS9c7gbjIOjSI5UkDOYRbIhnBfCdKcbE8itl7tJfQ8q7g==-----END EC PRIVATE KEY-----";
            Jwk publicSigningKey = MyInfoSecurityHelper.GetKeyFromKeyFile(publicSigningKeyJson, KeyFileFormat.JSON);
            Jwk privateSigningKey = MyInfoSecurityHelper.GetKeyFromKeyFile(privateSigningKeyPem, KeyFileFormat.PEM);
            EphemeralKeyPair ephemeralKeyPair = new EphemeralKeyPair()
            {
                PrivateKey = privateSigningKey,
                PublicKey = publicSigningKey,
            };

            string expectedPrint = "aQPyZ72NM043E4KEioaHWzixt0owV99gC9kRK388WoQ";


            string print = MyInfoSecurityHelper.GenerateJwkThumbprint(ephemeralKeyPair.PublicKey);
            //string token = MyInfoSecurityHelper.GenerateDPoP("https://sit.api.myinfo.gov.sg/com/v4/token", "POST", ephemeralKeyPair, "");
            Assert.IsTrue(expectedPrint == print);
        }
    }
}