### PRODUCTION ###

ifeq ($(wildcard ./.env),)
	$(error No dot env file in project root)
endif

include .env

# Connect to hosted db (opens a SQL shell)
connect:
	mysql --user $(DB_USER) --password=$(DB_PASSWORD) --host $(DB_HOST) --port $(DB_PORT) $(DB_NAME)


### DEVELOPMENT ###

# Start MailHog in the background then start the backend auth server
dev:
	@echo "Starting MailHog"
	~/go/bin/MailHog > mailhog.log 2>&1 &
	@echo "Starting app"
	chmod +x scripts/run.sh && . ./scripts/run.sh > app.log 2>&1

# Remove any log files generated
clean:
	rm -f -- mailhog.log && rm -f -- app.log
