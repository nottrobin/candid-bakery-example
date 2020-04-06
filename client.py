import os
from http.cookiejar import MozillaCookieJar

import click

from macaroonbakery import httpbakery

client = httpbakery.Client(cookies=MozillaCookieJar('.login'))
try:
    client.cookies.load(ignore_discard=True)
except:
    pass


@click.group()
def cli():
    pass


@cli.command()
def login():
    r = client.request('GET', 'http://localhost:5000/')
    data = r.json()
    client.cookies.save(ignore_discard=True)
    print('Hello {}!'.format(data['username']))


@cli.command()
def logout():
    os.remove('.login')


if __name__ == '__main__':
    cli()
