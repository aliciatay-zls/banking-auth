# Go Banking Web App - Authentication Server

## Running the app
1. Open this repo in another project window.

2. Ensure the db has been started in the [Resource Server app](https://github.com/udemy-go-1/banking-auth)

3. In terminal, run one of the following:
    * `./run.ps1` if using Powershell (e.g. Intellij terminal)
    * `./run.sh`

   An info-level log with the message "Starting the auth server..." will be printed to console on success.
   <br/><br/>
4. [Postman](https://www.postman.com/) can be used to send requests to the app. Sample requests:

| Method | API Endpoint                       | Query Params                               | Body                                             | Result                                                                                                                                                          |
|--------|------------------------------------|--------------------------------------------|--------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| POST   | http://localhost:8181/auth/login   |                                            | {"username": "2001", <br/>"password": "abc123"}  | Will successfully login as the user with username 2001, then display/return access token valid for 1 hour and refresh token valid for 1 month from current time |
| GET    | http://localhost:8181/auth/verify  | token, route_name, account_id, customer_id |                                                  | Will verify the client's request based on the token, then display/return authorization success or failure                                                       |
| POST   | http://localhost:8181/auth/refresh |                                            | {"access_token": ..., <br/>"refresh_token": ...} | Will check the tokens' validity and ability to refresh, then display/return a new access token valid for 1 hour from current time                               |

### Notes
* Tokens can be decoded using: https://jwt.io/
* Their expiry dates are in [Epoch time](https://datatracker.ietf.org/doc/html/rfc7519#section-2) (JSON numeric date 
type) and can be converted from human-readable dates using: https://www.epochconverter.com/
