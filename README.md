# Go Banking Web App - Authentication Server

## Running the app
1. Open this repo in another project window.

2. Ensure the db has been started in the [Resource Server app](https://github.com/udemy-go-1/banking-auth)

3. In terminal, start the MailHog SMTP server by running:
   ```
   ~/go/bin/MailHog
   ```

4. Open another tab in terminal and run one of the following:
    * `./run.ps1` if using Powershell (e.g. Intellij terminal)
    * `./run.sh`

   Info-level logs on starting the auth server and SMTP server will be printed to console on success.
   <br/><br/>
5. [Postman](https://www.postman.com/) can be used to send requests to the app. Sample requests:

| Method | API Endpoint                               | Query Params                               | Body                                                                                                                                                                                                                   | Result                                                                                                                                                                                                                                         |
|--------|--------------------------------------------|--------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| POST   | http://localhost:8181/auth/login           |                                            | {"username": "2001", <br/>"password": "abc123"}                                                                                                                                                                        | Will successfully login as the user with username 2001, then display/return access token valid for 1 hour and refresh token valid for 1 month from current time                                                                                |
| POST   | http://localhost:8181/auth/logout          |                                            | {"refresh_token": ...}                                                                                                                                                                                                 | Will check the refresh token's validity and end the session for the user, then return 200 to indicate successful logout or another status code otherwise                                                                                       |
| GET    | http://localhost:8181/auth/verify          | token, route_name, account_id, customer_id |                                                                                                                                                                                                                        | Will verify the client's request based on the token, then display/return authorization success or failure                                                                                                                                      |
| POST   | http://localhost:8181/auth/refresh         |                                            | {"access_token": ..., <br/>"refresh_token": ...}                                                                                                                                                                       | Will check the tokens' validity and ability to refresh, then display/return a new access token valid for 1 hour from current time                                                                                                              |
| POST   | http://localhost:8181/auth/continue        |                                            | {"access_token": ..., <br/>"refresh_token": ...}                                                                                                                                                                       | Will check the tokens' validity and existence in the store, then return 200 to indicate the user already logged in previously or another status code otherwise                                                                                 |
|        |                                            |                                            |                                                                                                                                                                                                                        |                                                                                                                                                                                                                                                |
| POST   | http://localhost:8181/auth/register        |                                            | { "full_name": "testing", <br/>"country": "testCountry", <br/>"zipcode": "123456", <br/>"date_of_birth": "2000-11-11", <br/>"email": "test@testmail.com", <br/>"username": "testUsername", <br/>"password": "test123"} | Will sign up as a customer who has 2 accounts opened for them automatically (a saving account of $30,0000 and a checking account of $6,000), then display/return the email address used during sign-up and the date this sign-up was processed |
| GET    | http://localhost:8181/auth/register/check  | ott                                        |                                                                                                                                                                                                                        | Will check the one-time token's validity and the registration, then return 200 to indicate that both are fine and the registration can go on to be confirmed if not already done.                                                              |
| POST   | http://localhost:8181/auth/register/finish |                                            |                                                                                                                                                                                                                        |                                                                                                                                                                                                                                                |

### Notes
* Tokens can be decoded using: https://jwt.io/
* Their expiry dates are in [Epoch time](https://datatracker.ietf.org/doc/html/rfc7519#section-2) (JSON numeric date 
type) and can be converted from human-readable dates using: https://www.epochconverter.com/
