#TODO: add support for non sudo / virtual envs
{% if update -%}
sudo apt-get update
{%- endif %}
sudo apt-get install -y {{packages}}
sudo rm /etc/cron.d/apt_install
rm -- "$0"

