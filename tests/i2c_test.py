import time
import unittest

from pi_setup.pi_setup import PiConfigurator
from pi_setup.sd_card import DeviceManager, select_sd_card


class MyTestCase(unittest.TestCase):
    def test_i2c(self):
        cards = DeviceManager.get_sd_cards()
        card = select_sd_card(cards)
        with card:
            time.sleep(1)

            print("----")
            configurator = PiConfigurator(card)
            configurator.enable_i2c(True)


if __name__ == '__main__':
    unittest.main()
