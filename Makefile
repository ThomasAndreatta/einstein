# Makefile derived from Taskfile.yml

# Ensure we export all variables to make them available to subprocesses
export

# Environment variables
ROOT := $(shell pwd)
RESULTS := $(ROOT)/results

##################################
# Pin/libdft vars
PIN_VERSION := pin-3.28-98749-g6643ecee5-gcc-linux
PIN_ROOT := $(ROOT)/src/misc/$(PIN_VERSION)
PIN := $(PIN_ROOT)/pin
LIBDFT := $(ROOT)/src/libdft64-ng
PIN_ARCH := intel64

##################################
# Build vars
INSTALL_DIR := $(ROOT)/build
CC := gcc-9
CXX := g++-9
AR := ar
CFLAGS := -fPIC -fPIE -Og -g
AR_FLAGS := -cru
LDFLAGS := -z max-page-size=0x1000
HAVE_LIBDFT := 1

##################################
# Misc vars
DEFAULT_CORES := $(ROOT)/results/misc/default-cores/
NPROC := $(shell nproc)

# Extra variables to pass to targets
TEST_ARG ?=
APP_NAME ?=
APP_ARGS ?=
JSON_PATH ?=

##############################################################################
## Setup targets ##############################################################

.PHONY: init init-submodule init-pkgs init-env init-getpin einstein-default-config db-init

init: init-submodule init-pkgs init-env init-getpin einstein-default-config db-init
	@echo "Initialized repo"

init-pkgs:
	sudo apt-get update && sudo apt-get -y upgrade
	sudo apt-get install -y cpanminus libpq-dev miller libldap2-dev libpam0g-dev libzstd-dev libbz2-dev libxxhash-dev libmaxminddb-dev liblua5.4-dev lldb gcovr smem gcc-9 g++-9 python3-pip postgresql prelink libpcre3-dev libxslt-dev libgeoip-dev libgd-dev libperl-dev libipc-run-perl bison flex libmemcached-tools libevent-dev gdb net-tools apache2-dev libcrypt-ssleay-perl
	pip install django tqdm pygdbmi psycopg2
	cpanm -S IPC::Run Time::Stopwatch Bundle::ApacheTest HTTP::DAV DateTime Time::HiRes Test::Harness Crypt::SSLeay Net::SSLeay IO::Socket::SSL IO::Socket::IP IO::Select LWP::Protocol::https AnyEvent AnyEvent::WebSocket::Client LWP::Protocol::AnyEvent::http FCGI

init-submodule:
	git submodule update --init --progress

init-getpin:
	cd src/misc && wget https://software.intel.com/sites/landingpage/pintool/downloads/$(PIN_VERSION).tar.gz && tar -xf $(PIN_VERSION).tar.gz && rm $(PIN_VERSION).tar.gz

init-env:
	# Set gcc-9 as the default
	sudo update-alternatives --remove-all gcc || true
	sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 110 --slave /usr/bin/g++ g++ /usr/bin/g++-9 --slave /usr/bin/gcov gcov /usr/bin/gcov-9
	# Enable userfaultfd (for libdft) and disable ptrace_scope (as advised by Pin's documentation)
	printf "vm.unprivileged_userfaultfd=1\nkernel.yama.ptrace_scope=0\n" | sudo tee /etc/sysctl.d/99-einstein.conf
	sudo sysctl -p /etc/sysctl.d/99-einstein.conf

##############################################################################
## cmdsvr targets ############################################################

.PHONY: cmdsvr-build cmdsvr-clean

cmdsvr-build:
	cd src/cmdsvr && make -j$(NPROC) -s

cmdsvr-clean:
	cd src/cmdsvr && make clean -j$(NPROC) -s

##############################################################################
## libdft targets ############################################################

.PHONY: libdft-build libdft-build-1tagperset libdft-clean libdft-test-all libdft-test

libdft-build:
	# Can add -DDEBUG_MEMTAINT and -DDEBUG_INFO here
	cd $(LIBDFT) && CPPFLAGS="-g -DLIBDFT_TAG_PTR -DLIBDFT_PTR_32 -DLIBDFT_TAG_SSET_MAX=16" make all -j$(NPROC) -s

libdft-build-1tagperset:
	# Can add -DDEBUG_MEMTAINT and -DDEBUG_INFO here
	cd $(LIBDFT) && CPPFLAGS="-g -DLIBDFT_TAG_PTR -DLIBDFT_PTR_32 -DLIBDFT_TAG_SSET_MAX=1" make all -j$(NPROC) -s

libdft-clean:
	cd $(LIBDFT) && make clean -j$(NPROC) -s

libdft-test-all:
	cd $(LIBDFT)/tests && make run-all

libdft-test:
	cd $(LIBDFT)/tests && make $(TEST_ARG).run

##############################################################################
## Einstein targets ##########################################################

.PHONY: einstein-build einstein-build-1tagperset einstein-build-rop einstein-clean einstein-test einstein-test-minimal einstein-default-config einstein-nowrite-config

einstein-build:
	cd src/einstein && CPPFLAGS='-DROOT=\"$(ROOT)\" -g -DLIBDFT_TAG_PTR -DLIBDFT_PTR_32 -DLIBDFT_TAG_SSET_MAX=16' make obj-intel64/einstein.so -j$(NPROC) -s

einstein-build-1tagperset:
	cd src/einstein && CPPFLAGS='-DROOT=\"$(ROOT)\" -g -DLIBDFT_TAG_PTR -DLIBDFT_PTR_32 -DLIBDFT_TAG_SSET_MAX=1' make obj-intel64/einstein.so -j$(NPROC) -s

einstein-build-rop:
	cd src/einstein && CPPFLAGS='-DROOT=\"$(ROOT)\" -g -DLIBDFT_TAG_PTR -DLIBDFT_PTR_32 -DLIBDFT_TAG_SSET_MAX=16 -DDFTROP' make obj-intel64/einstein.so -j$(NPROC) -s

einstein-clean:
	cd src/einstein && make clean -j$(NPROC) -s

einstein-test:
	rm -rf apps/tests/.tmp/*
	cp build/einstein-config.default.json build/einstein-config.json
	cd apps/tests && make clean -j$(NPROC) && make all -j$(NPROC) && make run-all
	$(MAKE) db-add-reports-test db-analyze-reports

einstein-test-minimal:
	rm -rf apps/tests/.tmp/*
	cp build/einstein-config.default.json build/einstein-config.json
	cd apps/tests && make clean -j$(NPROC) && make all -j$(NPROC) && make run-minimal

einstein-default-config:
	cp build/einstein-config.default.json build/einstein-config.json

einstein-nowrite-config:
	cp build/einstein-config.no-write.json build/einstein-config.json

##############################################################################
## Post-processing targets ###################################################

################################
#### Parsing

.PHONY: parse-tests parse-app parse-all

parse-tests:
	cd apps && ./parse-reports.sh tests > $(RESULTS)/reports/dtest.json

parse-app:
	# Parse reports for the app in APP_NAME
	cd apps && ./parse-reports.sh $(APP_NAME) > $(RESULTS)/reports/dcurrent.json

parse-all:
	# Parse all logs
	cd apps && ./parse-reports.sh ALL > $(RESULTS)/reports/$(shell date +"%Y-%m-%d-%H:%M:%S")_all.json
	cd $(RESULTS)/reports/ && rm -f dcurrent.json && ln -s $(shell date +"%Y-%m-%d-%H:%M:%S")_all.json dcurrent.json

################################
#### DB: Init/uninit

.PHONY: db-init db-uninit _db-change-defaults

db-init:
	# Create DB user with roles, etc.
	sudo -i -u postgres psql -c "CREATE USER einstein_user WITH PASSWORD 'einstein_password'"
	sudo -i -u postgres psql -c "ALTER ROLE einstein_user SET client_encoding TO 'utf8'"
	sudo -i -u postgres psql -c "ALTER ROLE einstein_user SET default_transaction_isolation TO 'read committed'"
	sudo -i -u postgres psql -c "ALTER ROLE einstein_user SET timezone TO 'UTC'"
	$(MAKE) db-create

db-uninit:
	# Undo db-init
	$(MAKE) db-clean
	sudo -i -u postgres psql -c "DROP USER einstein_user"

_db-change-defaults:
	# Change default DB variables to support more connections
	sudo -i -u postgres psql -c "ALTER SYSTEM SET max_connections TO 2000;"
	sudo -i -u postgres psql -c "ALTER SYSTEM SET shared_buffers TO '2800MB';"
	sudo service postgresql restart

################################
#### DB: Create/clean

.PHONY: _db-migrate db-create db-clean

_db-migrate:
	cd $(RESULTS) && ./db_manage.py makemigrations db && ./db_manage.py migrate

db-create:
	# Create DB
	sudo -i -u postgres psql -c "CREATE DATABASE einstein_db"
	sudo -i -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE einstein_db TO einstein_user"
	$(MAKE) _db-migrate

db-clean:
	# Remove DB
	cd $(RESULTS) && rm -rf db/migrations __pycache__ db/__pycache__ reports/reports.db
	$(MAKE) db-revoke-connections
	sudo -i -u postgres psql -c "DROP DATABASE einstein_db"

################################
#### DB: Save/revert

.PHONY: db-save db-revert

db-save:
	$(MAKE) db-revoke-connections
	sudo -i -u postgres psql -c "ALTER DATABASE einstein_db RENAME TO saved_einstein_db;"

db-revert:
	$(MAKE) db-revoke-connections db-backup-revoke-connections
	sudo -i -u postgres psql -c "ALTER DATABASE saved_einstein_db RENAME TO einstein_db;"

################################
#### DB: Add reports

.PHONY: _db-add-reports db-add-reports db-add-reports-test db-add-rop-reports

_db-add-reports:
	cd $(RESULTS) && ./db_main.py add_reports --json_path=$(JSON_PATH)

db-add-reports:
	$(MAKE) parse-all db-clean db-create
	$(MAKE) _db-add-reports JSON_PATH=reports/dcurrent.json

db-add-reports-test:
	$(MAKE) parse-tests
	$(MAKE) db-clean db-create
	$(MAKE) _db-add-reports JSON_PATH=reports/dtest.json

db-add-rop-reports:
	cd apps && ./parse-rop-reports.sh ALL > $(RESULTS)/reports/$(shell date +"%Y-%m-%d-%H:%M:%S")_ROP_all.json
	cd $(RESULTS)/reports/ && rm -f dcurrent_ROP.json && ln -s $(shell date +"%Y-%m-%d-%H:%M:%S")_ROP_all.json dcurrent_ROP.json
	$(MAKE) db-clean db-create
	cd $(RESULTS) && ./db_main.py add_rop_reports --json_path=reports/dcurrent_ROP.json && ./db_main.py analyze_rop_reports && ./db_main.py print_rop_candidates

################################
#### DB: Analysis, printing

.PHONY: db-analyze-reports db-analyze-reports-app db-analyze-reports-singleproc db-analyze-reports-app-singleproc db-analyze-candidates db-analyze-candidates-app db-reset-reports-analysis db-reset-candidates-analysis db-print-candidates db-print-exploits

db-analyze-reports:
	cd $(RESULTS) && ./db_main.py analyze_reports

db-analyze-reports-app:
	cd $(RESULTS) && ./db_main.py analyze_reports --app=$(APP_NAME)

db-analyze-reports-singleproc:
	cd $(RESULTS) && NPROC=1 ./db_main.py analyze_reports

db-analyze-reports-app-singleproc:
	cd $(RESULTS) && NPROC=1 ./db_main.py analyze_reports --app=$(APP_NAME)

db-analyze-candidates:
	cd $(RESULTS) && ./db_main.py analyze_candidates --root_path $(ROOT)

db-analyze-candidates-app:
	cd $(RESULTS) && ./db_main.py analyze_candidates --root_path $(ROOT) --app=$(APP_NAME)

db-reset-reports-analysis:
	cd $(RESULTS) && ./db_main.py reset_reports_analysis

db-reset-candidates-analysis:
	cd $(RESULTS) && ./db_main.py reset_candidates_analysis

db-print-candidates:
	cd $(RESULTS) && ./db_main.py print_candidates

db-print-exploits:
	cd $(RESULTS) && ./db_main.py print_exploits

################################
#### DB: Internal helpers

.PHONY: db-revoke-connections db-backup-revoke-connections db-list

db-revoke-connections:
	# Revoke any connections to einstein_db
	sudo -i -u postgres psql -c "REVOKE CONNECT ON DATABASE einstein_db FROM public"
	sudo -i -u postgres psql -c "SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.datname = 'einstein_db';"

db-backup-revoke-connections:
	# Revoke any connections to backup_einstein_db
	sudo -i -u postgres psql -c "REVOKE CONNECT ON DATABASE saved_einstein_db FROM public"
	sudo -i -u postgres psql -c "SELECT pg_terminate_backend(pg_stat_activity.pid) FROM pg_stat_activity WHERE pg_stat_activity.datname = 'saved_einstein_db';"

db-list:
	sudo -i -u postgres psql -c "\l"

##############################################################################
## App targets ###############################################################

.PHONY: app-build app-test app-eval app-eval-brief app-eval-custom app-eval-tmp

app-build:
	cd apps/$(APP_NAME) && ./build.inst

# Direct method execution to ensure consistency with task
app-test:
	$(MAKE) einstein-default-config apps-stop
	cd apps && ./simple-test.sh $(APP_ARGS)

app-eval:
	$(MAKE) einstein-default-config apps-stop
	cd apps/$(APP_NAME) && BENCH_TYPE=2 ./clientctl bench || true

app-eval-brief:
	timeout --preserve-status 2m $(MAKE) app-eval APP_NAME=$(APP_NAME)
	./apps/scripts/stop-all-servers.sh

app-eval-custom:
	./apps/scripts/stop-all-servers.sh
	cd apps/$(APP_NAME) && BENCH_TYPE=3 ./clientctl bench || true

app-eval-tmp:
	./apps/scripts/stop-all-servers.sh
	cd apps/$(APP_NAME) && BENCH_TYPE=4 ./clientctl bench || true

################################
#### nginx

.PHONY: nginx-build nginx-test nginx-eval nginx-eval-brief nginx-eval-custom nginx-eval-tmp nginx-parse-reports

nginx-build:
	$(MAKE) app-build APP_NAME=nginx-1.23.0

nginx-test:
	$(MAKE) app-test APP_ARGS=nginx-1.23.0

nginx-eval:
	$(MAKE) app-eval APP_NAME=nginx-1.23.0

nginx-eval-brief:
	$(MAKE) app-eval-brief APP_NAME=nginx-1.23.0

nginx-eval-custom:
	$(MAKE) app-eval-custom APP_NAME=nginx-1.23.0

nginx-eval-tmp:
	$(MAKE) app-eval-tmp APP_NAME=nginx-1.23.0

nginx-parse-reports:
	$(MAKE) parse-app APP_NAME=nginx-1.23.0

################################
#### lighttpd

.PHONY: lighttpd-build lighttpd-test lighttpd-eval lighttpd-eval-brief lighttpd-eval-custom lighttpd-eval-tmp lighttpd-parse-reports

lighttpd-build:
	$(MAKE) app-build APP_NAME=lighttpd-1.4.65

lighttpd-test:
	$(MAKE) app-test APP_ARGS="lighttpd-1.4.65 -f install/etc/lighttpd.conf"

lighttpd-eval:
	$(MAKE) app-eval APP_NAME=lighttpd-1.4.65

lighttpd-eval-brief:
	$(MAKE) app-eval-brief APP_NAME=lighttpd-1.4.65

lighttpd-eval-custom:
	$(MAKE) app-eval-custom APP_NAME=lighttpd-1.4.65

lighttpd-eval-tmp:
	$(MAKE) app-eval-tmp APP_NAME=lighttpd-1.4.65

lighttpd-parse-reports:
	$(MAKE) parse-app APP_NAME=lighttpd-1.4.65

################################
#### apache

.PHONY: apache-build apache-test apache-eval apache-eval-brief apache-eval-custom apache-eval-tmp apache-parse-reports

apache-build:
	$(MAKE) app-build APP_NAME=apache-2.4.54

apache-test:
	$(MAKE) app-test APP_ARGS="apache-2.4.54 -f $(ROOT)/apps/apache-2.4.54/myhttpd.conf -k start"

# If 'bench' or 'custom' doesn't work the first time, try running the commands under 'Configuring Apache test suite' in apps/apache-2.4.54/runbench
apache-eval:
	$(MAKE) app-eval APP_NAME=apache-2.4.54

apache-eval-brief:
	$(MAKE) app-eval-brief APP_NAME=apache-2.4.54

apache-eval-custom:
	$(MAKE) app-eval-custom APP_NAME=apache-2.4.54

apache-eval-tmp:
	$(MAKE) app-eval-tmp APP_NAME=apache-2.4.54

apache-parse-reports:
	$(MAKE) parse-app APP_NAME=apache-2.4.54

################################
#### postgres

.PHONY: postgres-build postgres-test postgres-eval postgres-eval-brief postgres-eval-custom postgres-eval-tmp postgres-parse-reports

postgres-build:
	$(MAKE) app-build APP_NAME=postgresql-15.1

postgres-test:
	$(MAKE) app-test APP_ARGS=postgresql-15.1

postgres-eval:
	$(MAKE) app-eval APP_NAME=postgresql-15.1

postgres-eval-brief:
	$(MAKE) app-eval-brief APP_NAME=postgresql-15.1

postgres-eval-custom:
	$(MAKE) app-eval-custom APP_NAME=postgresql-15.1

postgres-eval-tmp:
	$(MAKE) app-eval-tmp APP_NAME=postgresql-15.1

postgres-parse-reports:
	$(MAKE) parse-app APP_NAME=postgresql-15.1

################################
#### redis

.PHONY: redis-build redis-test redis-eval redis-eval-brief redis-eval-custom redis-eval-tmp redis-parse-reports

redis-build:
	$(MAKE) app-build APP_NAME=redis-7.0.5

redis-test:
	$(MAKE) app-test APP_ARGS=redis-7.0.5

redis-eval:
	$(MAKE) app-eval APP_NAME=redis-7.0.5

redis-eval-brief:
	$(MAKE) app-eval-brief APP_NAME=redis-7.0.5

redis-eval-custom:
	$(MAKE) app-eval-custom APP_NAME=redis-7.0.5

redis-eval-tmp:
	$(MAKE) app-eval-tmp APP_NAME=redis-7.0.5

redis-parse-reports:
	$(MAKE) parse-app APP_NAME=redis-7.0.5

################################
#### memcached

.PHONY: memcached-build memcached-test memcached-eval memcached-eval-brief memcached-eval-custom memcached-eval-tmp memcached-parse-reports

memcached-build:
	$(MAKE) app-build APP_NAME=memcached-1.6.17

memcached-test:
	$(MAKE) app-test APP_ARGS="memcached-1.6.17 -p 1080 -U 1080"

memcached-eval:
	$(MAKE) app-eval APP_NAME=memcached-1.6.17

memcached-eval-brief:
	$(MAKE) app-eval-brief APP_NAME=memcached-1.6.17

memcached-eval-custom:
	$(MAKE) app-eval-custom APP_NAME=memcached-1.6.17

memcached-eval-tmp:
	$(MAKE) app-eval-tmp APP_NAME=memcached-1.6.17

memcached-parse-reports:
	$(MAKE) parse-app APP_NAME=memcached-1.6.17

################################
#### toy-app

.PHONY: toy-build toy-test toy-eval

toy-build:
	$(MAKE) app-build APP_NAME=toy

toy-test:
	cp build/einstein-config.default.json build/einstein-config.json
	cd apps && ./stop-all-servers.sh
	cd apps && ./simple-test.sh toy

toy-eval:
	$(MAKE) app-eval APP_NAME=toy

################################
#### All apps

.PHONY: apps-stop apps-build apps-test apps-eval apps-eval-brief

apps-stop:
	cd apps && ./stop-all-servers.sh

apps-build:
	time ( $(MAKE) nginx-build lighttpd-build apache-build postgres-build redis-build memcached-build )

apps-test:
	$(MAKE) nginx-test lighttpd-test apache-test postgres-test redis-test memcached-test

apps-eval:
	$(MAKE) einstein-default-config nginx-eval lighttpd-eval apache-eval postgres-eval redis-eval memcached-eval

apps-eval-brief:
	$(MAKE) einstein-default-config nginx-eval-brief lighttpd-eval-brief apache-eval-brief postgres-eval-brief redis-eval-brief memcached-eval-brief

##############################################################################
# Report management

.PHONY: reports-clean reports-save rop-reports-save reports-revert rop-reports-revert

reports-clean:
	rm -rf apps/*/.tmp/* $(DEFAULT_CORES)/*

reports-save:
	# Move current reports from .tmp directory into a .tmp-old subdirectory
	cd apps/nginx-1.23.0     && mkdir -p .tmp-old && touch .tmp/x && mv .tmp/* .tmp-old/ && rm .tmp-old/x
	cd apps/lighttpd-1.4.65  && mkdir -p .tmp-old && touch .tmp/x && mv .tmp/* .tmp-old/ && rm .tmp-old/x
	cd apps/apache-2.4.54    && mkdir -p .tmp-old && touch .tmp/x && mv .tmp/* .tmp-old/ && rm .tmp-old/x
	cd apps/postgresql-15.1  && mkdir -p .tmp-old && touch .tmp/x && mv .tmp/* .tmp-old/ && rm .tmp-old/x
	cd apps/redis-7.0.5      && mkdir -p .tmp-old && touch .tmp/x && mv .tmp/* .tmp-old/ && rm .tmp-old/x
	cd apps/memcached-1.6.17 && mkdir -p .tmp-old && touch .tmp/x && mv .tmp/* .tmp-old/ && rm .tmp-old/x

rop-reports-save:
	# Move current reports from .tmp directory into a .tmp-old-rop subdirectory
	cd apps/nginx-1.23.0     && mkdir -p .tmp-old-rop && touch .tmp/x && mv .tmp/* .tmp-old-rop/ && rm .tmp-old-rop/x
	cd apps/lighttpd-1.4.65  && mkdir -p .tmp-old-rop && touch .tmp/x && mv .tmp/* .tmp-old-rop/ && rm .tmp-old-rop/x
	cd apps/apache-2.4.54    && mkdir -p .tmp-old-rop && touch .tmp/x && mv .tmp/* .tmp-old-rop/ && rm .tmp-old-rop/x
	cd apps/postgresql-15.1  && mkdir -p .tmp-old-rop && touch .tmp/x && mv .tmp/* .tmp-old-rop/ && rm .tmp-old-rop/x
	cd apps/redis-7.0.5      && mkdir -p .tmp-old-rop && touch .tmp/x && mv .tmp/* .tmp-old-rop/ && rm .tmp-old-rop/x
	cd apps/memcached-1.6.17 && mkdir -p .tmp-old-rop && touch .tmp/x && mv .tmp/* .tmp-old-rop/ && rm .tmp-old-rop/x

reports-revert:
	# Delete current reports and move old reports from .tmp-old directory into .tmp subdirectory
	$(MAKE) reports-clean
	cd apps/nginx-1.23.0     && touch .tmp-old/x && mv .tmp-old/* .tmp/ && rm .tmp/x
	cd apps/lighttpd-1.4.65  && touch .tmp-old/x && mv .tmp-old/* .tmp/ && rm .tmp/x
	cd apps/apache-2.4.54    && touch .tmp-old/x && mv .tmp-old/* .tmp/ && rm .tmp/x
	cd apps/postgresql-15.1  && touch .tmp-old/x && mv .tmp-old/* .tmp/ && rm .tmp/x
	cd apps/redis-7.0.5      && touch .tmp-old/x && mv .tmp-old/* .tmp/ && rm .tmp/x
	cd apps/memcached-1.6.17 && touch .tmp-old/x && mv .tmp-old/* .tmp/ && rm .tmp/x

rop-reports-revert:
	# Delete current reports and move old reports from .tmp-old-rop directory into .tmp subdirectory
	$(MAKE) reports-clean
	cd apps/nginx-1.23.0     && touch .tmp-old-rop/x && mv .tmp-old-rop/* .tmp/ && rm .tmp/x
	cd apps/lighttpd-1.4.65  && touch .tmp-old-rop/x && mv .tmp-old-rop/* .tmp/ && rm .tmp/x
	cd apps/apache-2.4.54    && touch .tmp-old-rop/x && mv .tmp-old-rop/* .tmp/ && rm .tmp/x
	cd apps/postgresql-15.1  && touch .tmp-old-rop/x && mv .tmp-old-rop/* .tmp/ && rm .tmp/x
	cd apps/redis-7.0.5      && touch .tmp-old-rop/x && mv .tmp-old-rop/* .tmp/ && rm .tmp/x
	cd apps/memcached-1.6.17 && touch .tmp-old-rop/x && mv .tmp-old-rop/* .tmp/ && rm .tmp/x