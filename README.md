# MyInfo Connector for .Net

MyInfo Connector aims to simplify consumer's integration effort with MyInfo by providing an easy to use .NET library to integrate into your application.
Refer to [Java](https://github.com/singpass/myinfo-connector-v4-java) MyInfo-V4 connector, [myinfo-demo-app-v4](https://github.com/singpass/myinfo-demo-app-v4) demo app. 
 I made a myinfo v4 connector using .NET 7.

## Requirements

.NET 7

### 1.1 NuGet Package Installation

Add the following nuget packages to your application.

```xml
jose-jwt
Newtonsoft.Json
```

### 1.2 Configuration properties

You are required to pass properties to connector. Samples of the properties can be found in this repository under the Sample Properties folder.
| Required Properties | Description |
| -------- | ----------- |
| ClientId | Unique ID provided upon approval of your application to use MyInfo. For our sample application, it is **STG2-MYINFO-SELF-TEST** |
| RedirectUrl | The callback URL specified when invoking the authorise call. For our sample application, it is http://localhost:3001/callback |
| Scope | Space separated list of attributes requested. Possible attributes are listed in the Person object definition in the API specifications. |
| TokenUrl | Specify the TOKEN API URL for MyInfo. The API is available in two environments:<br> TEST: **https://test.api.myinfo.gov.sg/com/v4/token**<br> PROD:  **https://api.myinfo.gov.sg/com/v4/token** |
| PersonUrl | Specify the TOKEN API URL for MyInfo. The API is available in two environments:<br> TEST: **https://test.api.myinfo.gov.sg/com/v4/person**<br> PROD:  **https://api.myinfo.gov.sg/com/v4/person** |
| AuthoriseJWKSUrl | The URL to retrieve authorize JWKS public key. The url is available in two environments:<br> TEST: **https://test.authorise.singpass.gov.sg/.well-known/keys.json**<br> PROD:  **https://authorise.singpass.gov.sg/.well-known/keys.json** |
| MyInfoJWKSUrl | The URL to retrieve Myinfo JWKS public key. The url is available in two environments:<br> TEST: **https://test.myinfo.singpass.gov.sg/.well-known/keys.json**<br> PROD:  **https://myinfo.singpass.gov.sg/.well-known/keys.json** |


## Quick Start

### 2.1 RUN MyInfo Connector API Tester

Navigate to MyInfoConnector.API folder and run the test app.

```cmd
dotnet run
```

### 2.2 Open http://localhost:3001/ in Browser

