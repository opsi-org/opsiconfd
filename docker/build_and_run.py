#!/usr/bin/python3

import os
import argparse
import subprocess

os.chdir(os.path.dirname(os.path.realpath(__file__)))

#subprocess.call(['podman', 'build', '-t', 'opsiconfd:dev', '-f', './Dockerfile'])
#subprocess.call(['poetry', 'run', 'podman-compose', 'up'])

parser = argparse.ArgumentParser(description="Build and run docker compose environment.")
parser.add_argument("--type", choices=("dev", "load-balance", "compare41"), default="dev", help="Which type of environment to build and run")
args = parser.parse_args()

subprocess.call([
	"docker", "stop",
	"docker_mysql_1", "docker_redis_1", "docker_grafana_1", "docker_traefik_1",
	"docker_opsiconfd_1", "docker_opsiconfd_2", "docker_opsiconfd_3", "docker_opsiconfd_4",
	"docker_opsiconfd_1_1", "docker_opsiconfd_2_1",
	"docker_opsiconfd41_1", "docker_opsiconfd42_1"
])

if args.type == "load-balance":
	subprocess.call(["docker-compose", "-f", f"{args.type}-docker-compose.yml", "up", "--build", "--scale", "opsiconfd=2"])
elif args.type == "compare41":
	subprocess.call(["docker-compose", "-f", f"{args.type}-docker-compose.yml", "up", "--build"])
