#!/bin/bash
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get -yq install ddclient
sudo service ddclient restart
sudo rm /etc/cron.d/install_ddns
rm -- "$0"