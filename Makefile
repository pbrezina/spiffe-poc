up:
	docker-compose up

down:
	docker-compose down -v
	rm -f certs/tmp/*

stop:
	docker-compose stop

update-ca-bundle:
	./setup/update-ca-bundle.sh

first-time-up:
	docker compose up -d --wait --build spire-server ipa
	./setup/import-entries.sh
	./setup/setup-ipa-keytab.sh
	docker compose up -d --wait spire-agent
	docker-compose up
