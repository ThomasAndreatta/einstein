sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b  /bin/
update-rc.d postgresql enable

sleep 10
service postgresql start