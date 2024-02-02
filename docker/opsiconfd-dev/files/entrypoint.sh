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

if mkdir .venv 2>/dev/null; then
	echo "* Setup poetry venv"
	poetry lock --no-update
	poetry install --no-interaction --no-ansi
	[ -n "$DEV_USER" ] && chown -R $DEV_USER /workspace
else
	echo "* Waiting until poetry venv is set up"
	start_time=$(date +%s)
	last_file_count=1
	file_count=0
	# Wait until running poetry install is completed
	while [ $file_count -ne $last_file_count ]; do
		last_file_count=$file_count
		sleep 5
		file_count=$(find .venv -type f | wc -l)
	done
	end_time=$(date +%s)
	diff=$((end_time - start_time))
	echo "venv ready after ${diff} seconds"
fi

touch /run/.docker-healthy
# Run CMD
exec "$@"
