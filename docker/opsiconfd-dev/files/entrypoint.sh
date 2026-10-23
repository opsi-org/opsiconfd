#!/bin/sh

echo "* Running as $(whoami)"

cd /workspace

EDITOR="code"
if which cursor > /dev/null 2>&1; then
	EDITOR="cursor"
fi

update-alternatives --set editor /usr/bin/vim.basic

mkdir -p /var/log/opsi
mkdir -p /var/lib/opsi/depot
mkdir -p /var/lib/opsi/public
mkdir -p /var/lib/opsi/repository
mkdir -p /var/lib/opsi/workbench
mkdir -p /var/lib/opsiconfd
mkdir -p /tftpboot
ln -s /workspace/addons /var/lib/opsiconfd/addons

echo "* Fetch a test license"
mkdir -p /etc/opsi/licenses
wget --header="Authorization: Bearer ${OPSILICSRV_TOKEN}" "https://opsi-license-server.uib.gmbh/api/v1/licenses/test?usage=opsiconfd-dev-container" -O /etc/opsi/licenses/test.opsilic || true

echo "* Upgrade opsi-dev-cli"
opsi-dev-cli self upgrade --system || true

opsi-set-rights

echo "* Git config"
git config --global --replace-all core.editor "${EDITOR} --wait"
# /workspace is a bind mount owned by the host user
git config --global --replace-all safe.directory /workspace

OPSICONFD_BASE_DIR=/workspace
if [ -d $OPSICONFD_BASE_DIR ]; then
	state_file="$OPSICONFD_BASE_DIR/.venv_state"
	state_lock="$OPSICONFD_BASE_DIR/.venv_state_lock"

	touch "$OPSICONFD_BASE_DIR/docker.$(hostname)"

	while true; do
		if mkdir "$state_lock" 2>/dev/null; then
			echo "state lock acquired: $state_lock ($(date +"%Y-%m-%d %H:%M:%S.%N"))"
			break
		fi
		sleep 3
	done

	stat $state_file || true
	state=$(cat $state_file || true 2>/dev/null)
	echo "venv state: ${state}"

	if [ "$state" = "ready" ]; then
		echo "* opsiconfd venv is ready"
		echo "release state lock: $state_lock ($(date +"%Y-%m-%d %H:%M:%S.%N"))"
		rmdir "$state_lock"
	elif [ "$state" = "setup" ]; then
		echo "release state lock: $state_lock ($(date +"%Y-%m-%d %H:%M:%S.%N"))"
		rmdir "$state_lock"
		echo "* Waiting until opsiconfd venv is set up"
		start_time=$(date +%s)
		i=1
		while [ "$i" -le 100 ]; do
			state=$(cat $state_file 2>/dev/null)
			[ "$state" = "ready" ] && break
			sleep 3
			i=$((i+1))
		done
		end_time=$(date +%s)
		diff=$((end_time - start_time))
		if [ "$state" = "ready" ]; then
			echo "venv ready after ${diff} seconds"
		else
			echo "timed out waiting for venv after ${diff} seconds"
		fi
	else
		echo "* Setup opsiconfd venv"
		echo -n "setup" > $state_file
		sync
		echo "State \"setup\" written to $state_file ($(date +"%Y-%m-%d %H:%M:%S.%N"))"
		sleep 2
		echo "release state lock: $state_lock ($(date +"%Y-%m-%d %H:%M:%S.%N"))"
		rmdir "$state_lock"
		cd $OPSICONFD_BASE_DIR
		rm -rf ".venv"
		echo "Running uv sync"
		uv sync --frozen || (
			echo "uv sync failed: $?"
			exit 1
		)
		echo "uv completed"
		sleep 3
		echo -n "ready" > $state_file
		sync
		echo "venv created"
	fi
fi

touch /run/.docker-healthy

# Run CMD
echo "* Running: $@"
set +e
$@
exit_code=$?
echo "Exit code: $exit_code"
if [ "$exit_code" = 139 -o "$exit_code" = 135 ]; then
	echo "Trying again in 3 seconds"
	sleep 3
	$@
	exit_code=$?
	echo "Exit code: $exit_code"
fi
exit $exit_code
