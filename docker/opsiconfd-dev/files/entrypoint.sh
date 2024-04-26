#!/bin/sh

echo "* Running as $(whoami)"

cd /workspace

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

if [ -n "$DEV_USER" ]; then
	if [ -z "$SSH_AUTH_SOCK" ]; then
		VSCODE_AUTH_SOCK=$(ls -t /tmp/vscode-ssh-auth-*.sock 2> /dev/null | head -n1)
		[ -n "$VSCODE_AUTH_SOCK" ] && export SSH_AUTH_SOCK=$VSCODE_AUTH_SOCK
	fi
	ssh-add -L

	echo "* Git config"
	chown -R $DEV_USER /workspace
	su - $DEV_USER -c 'git config --global core.editor "code --wait"'
fi

OPSICONFD_BASE_DIR=/workspace
if [ -d $OPSICONFD_BASE_DIR ]; then
	mkdir -p $OPSICONFD_BASE_DIR/.venv
	state_file="$OPSICONFD_BASE_DIR/.venv/.venv_state"
	state_lock="$OPSICONFD_BASE_DIR/.venv/.venv_state_lock"

	while true; do
		if mkdir "$state_lock" 2>/dev/null; then
			echo "* State lock acquired: $state_lock"
			break
		fi
		sleep 3
	done

	state=$(cat $state_file 2>/dev/null)
	echo "venv state: ${state}"

	if [ "$state" = "ready" ]; then
		echo "* opsiconfd poetry venv is ready"
		rmdir "$state_lock"
	elif [ "$state" = "setup" ]; then
		echo "* Waiting until opsiconfd poetry venv is set up"
		rmdir "$state_lock"
		start_time=$(date +%s)
		i=1
		while [ "$i" -le 60 ]; do
			state=$(cat $state_file 2>/dev/null)
			[ "$state" = "ready" ] && break
			sleep 2
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
		echo "* Setup opsiconfd poetry venv"
		echo -n "setup" > $state_file
		rmdir "$state_lock"
		cd $OPSICONFD_BASE_DIR
		poetry lock --no-update
		poetry install --no-interaction --no-ansi
		[ -n "$DEV_USER" ] && chown -R $DEV_USER $OPSICONFD_BASE_DIR
		echo -n "ready" > $state_file
		echo "venv created"
	fi
fi

touch /run/.docker-healthy
# Run CMD
exec "$@"
