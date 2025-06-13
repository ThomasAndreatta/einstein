sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b  /bin
update-rc.d postgresql enable

apt-get install apt-get install postgresql postgresql-contrib

service postgresql start
sleep 5