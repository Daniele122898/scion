#!/bin/bash

if [ "$1" ]
    then
        kill -s SIGTERM $1;
fi

sudo unlink /tmp/supervisor.sock

supervisor/supervisor.sh reload;
supervisor/supervisor.sh start all;
