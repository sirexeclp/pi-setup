#TODO: add support for non sudo / virtual envs
sudo pip3 install{{" --upgrade" if upgrade else ""}}\
 --no-index -f {{destination}}{{" --user" if user else ""}}\
 {% if package is not none %}{{package}}{% else %}-r {{requirements}}{% endif %}
sudo rm /etc/cron.d/pip_install
rm -- "$0"