using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.FileProviders;
using MyInfoConnector;


internal class Program
{
    public class GetPersonDataBody
    {
        public  string AuthCode { get; init; }
        public  string CodeVerifier { get; init; }
    };

    private static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var app = builder.Build();

        var myInfoSettings = builder.Configuration.GetSection("MyInfo");
        string usingEnvironment = myInfoSettings["UsingEnvironment"].ToString();

        MyInfoConnectorConfig myinfoConfig = new MyInfoConnectorConfig()
        {
            ClientId = myInfoSettings[$"{usingEnvironment}:ClientId"].ToString(),
            RedirectUrl = myInfoSettings[$"{usingEnvironment}:RedirectUrl"].ToString(),
            Scope = myInfoSettings[$"{usingEnvironment}:Scope"].ToString(),
            AuthoriseJWKSUrl = myInfoSettings[$"{usingEnvironment}:AuthoriseJWKSUrl"].ToString(),
            MyInfoJWKSUrl = myInfoSettings[$"{usingEnvironment}:MyInfoJWKSUrl"].ToString(),
            TokenUrl = myInfoSettings[$"{usingEnvironment}:TokenUrl"].ToString(),
            PersonUrl = myInfoSettings[$"{usingEnvironment}:PersonUrl"].ToString(),
        };

        MyInfoConnector.MyInfoConnector myInfoConnector = MyInfoConnector.MyInfoConnector.Create(myinfoConfig);

        app.UseFileServer(new FileServerOptions
        {
            FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "Public")),
            EnableDefaultFiles = true,
            RequestPath = "",
        });

        app.UseFileServer(new FileServerOptions
        {
            FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "Public")),
            EnableDefaultFiles = true,
            RequestPath = "/callback",
        });

        #region "APIS"
        app.MapGet("/getEnv", () =>
        {
            return Results.Json(new
            {
                clientId = myInfoSettings[$"{usingEnvironment}:ClientId"],
                purpose_id = myInfoSettings[$"{usingEnvironment}:PurposeId"],
                redirectUrl = myInfoSettings[$"{usingEnvironment}:RedirectUrl"],
                scope = myInfoSettings[$"{usingEnvironment}:Scope"],
                authApiUrl = myInfoSettings[$"{usingEnvironment}:AuthorizeUrl"],
            });
        });

        app.MapPost("/generateCodeChallenge", () =>
        {
            var codes = myInfoConnector.GeneratePKCECodePair();
            return Results.Json(new
            {
                codeVerifier = codes.Item1,
                codeChallenge = codes.Item2,
            });
        });

        app.MapPost("/getPersonData", async ([FromBody]GetPersonDataBody getPersonDataBody) =>
        {
            string privateSigningKey = MyInfoSecurityHelper.GetJsonFromKeyFile(Path.Combine(Directory.GetCurrentDirectory(), myInfoSettings[$"{usingEnvironment}:AppClientPrivateSigningKeyFilePath"]));
            string privateEncryptionKey = MyInfoSecurityHelper.GetJsonFromKeyFile(Path.Combine(Directory.GetCurrentDirectory(), myInfoSettings[$"{usingEnvironment}:AppClientPrivateEncryptionKeyFilePath"]));
            string personJson =  await myInfoConnector.GetMyInfoPersonJson(getPersonDataBody.AuthCode, getPersonDataBody.CodeVerifier, privateSigningKey, privateEncryptionKey);
            return Results.Json(new
            {
                personJson = personJson
            });
        });
        #endregion

        app.Run("http://localhost:3001");
    }
}