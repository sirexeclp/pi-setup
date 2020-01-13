#! /bin/bash

serial_device="/dev/ttyAMA0"
erika_speed="1200"
rpirtsrtc_repo="git://github.com/mholling/rpirtscts.git"
device_tree_url="https://github.com/HiassofT/AtariSIO/raw/master/contrib/rpi/uart-ctsrts.dtbo"
device_tree_destination="/boot/overlays"

# Disable Bluetooth on the RPi 3 B+ so that we can use the serial port.
# already configured offline
# sudo sh -c 'echo "dtoverlay=pi3-disable-bt" >> /boot/config.txt'

#disable the system service that initialises the modem so it doesn’t use the UART
sudo systemctl disable hciuart
sudo systemctl stop hciuart

#enable ctsrts
git clone $rpirtsrtc_repo
cd rpirtscts
make
sudo ./rpirtscts on
#apply device tree
wget $device_tree_url -P $device_tree_destination
sudo sh -c 'echo "dtoverlay=uart-ctsrts" >> /boot/config.txt'



sudo stty -F $serial_device crtscts
sudo stty -F $serial_device speed $erika_speed



# TODO: disable serial console ; or do it offline ?
# sed -i -e 's/console=serial0,115200//g' /boot/cmdline.txt

#diable serial console as in raspi-config
#sed -i /boot/cmdline.txt -e "s/console=ttyAMA0,[0-9]\+ //"
#sed -i /boot/cmdline.txt -e "s/console=serial0,[0-9]\+ //"

#enable serial hardware as in raspi-config
#regex from raspi-config
#"^#?%s*"..key.."=.*$"
#enable_uart=1 > /boot/config.txt


# remove payload from target
sudo rm /etc/cron.d/configure_serial
rm -- "$0"