# Banking Web App - backend auth server
This repo contains code for the backend auth server.

The backend resource server [(separate repo)](https://github.com/aliciatay-zls/banking) and most of the auth server (added some features) were
built under the Udemy course ["REST based microservices API development in Golang"](https://www.udemy.com/course/rest-based-microservices-api-development-in-go-lang/).

## Setup
1. Install MailHog: https://github.com/mailhog/MailHog

2. Configure environment variables.
   * Development: set values in the scripts in `scripts/` if not using the dummy values
   * Production: create a `.env` file at project root with the same keys as the scripts in `scripts/`

## Running the app (Development)
1. Ensure the db has been started in the [other repo](https://github.com/aliciatay-zls/banking)

2. Open this repo in another project window.

3. In terminal, start the MailHog SMTP and backend auth servers:
   ```
   make dev
   ```
   In separate terminal tab, view logs for both in real-time without them interleaving:
   ```
    tail -f mailhog.log app.log
   ```
   On success, logs printed:
   * MailHog: will end with "Creating API v2 with WebPath:"
   * Backend auth server: will be an info-level log with the message "Starting auth server..."

4. [Postman](https://www.postman.com/) can be used to send requests to the app. Sample requests:

   | Method | API Endpoint                                | Query Params                               | Body                                                                                                                                                                                                                       | Result                                                                                                                                                                                                                                         |
   |--------|---------------------------------------------|--------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
   | POST   | https://localhost:8181/auth/login           |                                            | {"username": "2001", <br/>"password": "abc123"}                                                                                                                                                                            | Will successfully login as the user with username 2001, then display/return access token valid for 1 hour and refresh token valid for 1 month from current time                                                                                |
   | POST   | https://localhost:8181/auth/logout          |                                            | {"refresh_token": ...}                                                                                                                                                                                                     | Will check the refresh token's validity and end the session for the user, then return 200 to indicate successful logout or another status code otherwise                                                                                       |
   | GET    | https://localhost:8181/auth/verify          | token, route_name, account_id, customer_id |                                                                                                                                                                                                                            | Will verify the client's request based on the token, then display/return authorization success or failure                                                                                                                                      |
   | POST   | https://localhost:8181/auth/refresh         |                                            | {"access_token": ..., <br/>"refresh_token": ...}                                                                                                                                                                           | Will check the tokens' validity and ability to refresh, then display/return a new access token valid for 1 hour from current time                                                                                                              |
   | POST   | https://localhost:8181/auth/continue        |                                            | {"access_token": ..., <br/>"refresh_token": ...}                                                                                                                                                                           | Will check the tokens' validity and existence in the store, then return 200 to indicate the user already logged in previously or another status code otherwise                                                                                 |
   |        |                                             |                                            |                                                                                                                                                                                                                            |                                                                                                                                                                                                                                                |
   | POST   | https://localhost:8181/auth/register        |                                            | {"full_name": "testing", <br/>"country": "testCountry", <br/>"zipcode": "123456", <br/>"date_of_birth": "2000-11-11", <br/>"email": "test@testmail.com", <br/>"username": "testUsername", <br/>"password": "Test1234567!"} | Will sign up as a customer who has 2 accounts opened for them automatically (a saving account of $30,0000 and a checking account of $6,000), then display/return the email address used during sign-up and the date this sign-up was processed |
   | GET    | https://localhost:8181/auth/register/check  | ott                                        |                                                                                                                                                                                                                            | Will check the one-time token's validity and the registration, then return 200 to indicate that both are fine and the registration can go on to be confirmed if not already done                                                               |
   | GET    | https://localhost:8181/auth/register/resend | ott                                        |                                                                                                                                                                                                                            | Will send a new confirmation link to the same email used in the registration (retrieved from the token)                                                                                                                                        |
   | POST   |                                             |                                            | {"email": "test@testmail.com"}                                                                                                                                                                                             | Will send a new confirmation link to the same email used in the registration                                                                                                                                                                   |
   | POST   | https://localhost:8181/auth/register/finish |                                            | {"one_time_token": ...}                                                                                                                                                                                                    | Will complete the registration process                                                                                                                                                                                                         |

5. Update all packages periodically to the latest version:
   ```
   go get -u all
   go mod tidy
   ```
