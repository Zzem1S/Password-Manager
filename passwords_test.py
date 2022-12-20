import pytest

from lib.client import Client
from lib.server import Server

#   Need to start server before running tests
# $ python3 run_server.py 127.0.0.1 8080

client = Client("http://localhost:8080")


def test_add_password():
    assert client.add_password("test", "test", "test", "test") == "Password added"

def test_get_passwords():
    assert client.get_passwords("test", "test") == '{"test": "test"}'

def test_incorrect_master_password():
    assert client.get_passwords("test", "incorrect") == "Bad master password or username"