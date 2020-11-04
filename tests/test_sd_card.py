import unittest

from pi_setup.sd_card import DeviceManager, select_sd_card


class MyTestCase(unittest.TestCase):
    def test_mount(self):
        self.assertEqual(True, False)

    def test_ls_sd_cards(self):
        cards = DeviceManager.get_sd_cards()
        print(cards)

    def test_auto_select(self):
        cards = DeviceManager.get_sd_cards()
        card = select_sd_card(cards)
        print(card)

    def test_mount(self):
        cards = DeviceManager.get_sd_cards()
        card = select_sd_card(cards)
        card.unmount_children()
        card.mount_children()
        card.unmount_children()


if __name__ == '__main__':
    unittest.main()
