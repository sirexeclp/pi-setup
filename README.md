# pi-setup

This project aims to develop a simple tool for automated headless setup of raspberry pis.

Planned features are:

- enabling SSH
- setting up wifi
- setting up SSH with pubkey authentication
- setting a static ip for direct ethernet connection (maybe also configure your pc for the network)
- changing default user and password
- setting up dynamic dns
- changing hostname

## Quickstart

This tool requires root privileges to write to the /rootfs partition of the sd card
and to read some configuration files on the host (eg. wifi).

To get some info about the sd-card, you can use the status command:

```
sudo python3 -m pi_setup status  
```

You can list the recognised sd-cards

```bash
sudo python3 -m pi_setup cards list
```

To flash a config use the setup command:

```
sudo python3 -m pi_setup setup <config.yaml>
```
