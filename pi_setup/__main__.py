import click as click
from pi_setup import dashboard, pi_setup
from pi_setup.sd_card import DeviceManager


@click.group()
def cli():
    pass


@click.command()
def status():
    dashboard.main()


@click.command()
@click.argument("config_path")
def setup(config_path: str):
    pi_setup.main(config_path)


@click.group()
def cards():
    pass


@click.command()
def list():
    sd_cards = DeviceManager.get_sd_cards()
    #print([x.label for x in sd_cards])
    for x in sd_cards:
        x.pretty_print()

if __name__ == '__main__':
    cli.add_command(status)
    cli.add_command(setup)

    cli.add_command(cards)
    cards.add_command(list)

    cli()
