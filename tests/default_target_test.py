import time
import unittest

from pi_setup.pi_setup import PiConfigurator
from pi_setup.sd_card import DeviceManager, select_sd_card


class MyTestCase(unittest.TestCase):
    def test_read_target(self):
        cards = DeviceManager.get_sd_cards()
        card = select_sd_card(cards)
        with card:
            time.sleep(1)

            print("----")
            configurator = PiConfigurator(card)
            configurator.set_default_target("graphical")
            configurator.set_autologin("pi")
            configurator.tty_service()
            print(configurator.get_default_target())


if __name__ == '__main__':
    unittest.main()
