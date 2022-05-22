#!/bin/bash

if [ "$1" ]
    then
        kill -s SIGTERM $1;
fi


supervisor/supervisor.sh reload;
supervisor/supervisor.sh start all;
