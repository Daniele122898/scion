#!/bin/bash

echo "building go/co"
go build -o ./bin/ ./go/co/
echo "building go/cs"
go build -o ./bin/ ./go/cs/
echo "building go/daemon"
go build -o ./bin/ ./go/daemon/
echo "building go/dispatcher"
go build -o ./bin/ ./go/dispatcher/
echo "building go/posix-router"
go build -o ./bin/ ./go/posix-router/
echo "building go/scion-pki"
go build -o ./bin/ ./go/scion-pki/

# echo "setup for minimal run"
# rm -rf gen* logs
export PYTHONPATH=python/:.
#printf '#!/bin/bash\necho "0.0.0.0"' > tools/docker-ip
# python3 python/topology/generator.py -c ./topology/tiny4.topo
# rm gen/jaeger-dc.yml
# mkdir gen-cache

echo "Please kill old supervisor instance listed below using kill -s SIGTERM <pid> then call reload and start all"
ps -ef | grep supervisord
