#!/usr/bin/env python3

import argparse

from user_requests import login_user
from encryption import make_password_ready

arg_parser = argparse.ArgumentParser(description="Login user")
arg_parser.add_argument("username", type=str, help="username")
arg_parser.add_argument("password", type=str, help="password")


def parse_args():
    args = arg_parser.parse_args()
    return args.username, args.password


if __name__ == "__main__":
    username, password = parse_args()
    print(login_user(username, make_password_ready(password)))
