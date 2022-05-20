#!/bin/bash

kill -s SIGTERM $1
sudo unlink /tmp/supervisor.sock
