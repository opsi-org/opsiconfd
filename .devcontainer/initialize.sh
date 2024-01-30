base_dir=$(dirname $(readlink -f $0))/..
env_file=${base_dir}/docker/opsiconfd-dev/local.env

touch $env_file

for env_var in "OPSILICSRV_URL" "OPSILICSRV_TOKEN"; do
	if ! grep --quiet $env_var $env_file; then
		echo "$env_var=" >> $env_file
	fi
done

if ! grep --quiet "OPSICONFD_FORWARD_PORT" $env_file; then
	echo "OPSICONFD_FORWARD_PORT=4448:" >> $env_file
fi
#env_file=${base_dir}/docker/opsiconfd-dev/.env
#sed -i '/^LOCAL_WORKSPACE_DIR/d' $env_file
#echo "LOCAL_WORKSPACE_DIR=${base_dir}" >> $env_file
