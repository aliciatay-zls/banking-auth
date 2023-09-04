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

| Method | URL                              | Body                                            | Result                                                                                                            |
|--------|----------------------------------|-------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| POST   | http://localhost:8181/auth/login | {"username": "2001", <br/>"password": "abc123"} | Will successfully login as the user with username 2001, then display a new token generated for this login session |

Tokens can be decoded using: https://jwt.io/
