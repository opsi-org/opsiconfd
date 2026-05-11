while [ ! -f /run/.docker-healthy ]; do
	echo "Waiting for container to be healthy (post_start.sh)..."
	sleep 3
done
echo "Container is healthy (post_start.sh)"

git config --replace-all core.editor "code --wait"
sudo chown -R "$USER" "$HOME" /workspace
uv sync
