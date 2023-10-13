#!/usr/bin/env python3

import argparse
import sys
import time
import requests

from user_requests import login_user
from encryption import make_password_ready

arg_parser = argparse.ArgumentParser(description="Login user")
arg_parser.add_argument("username", type=str, help="username")
arg_parser.add_argument("password", type=str, help="password")

arg_parser.add_argument(
    "--interval",
    type=int,
    help="interval in seconds to repeat",
    default=None,
    required=False,
)


def parse_args():
    args = arg_parser.parse_args()
    return args.username, args.password, args.interval


if __name__ == "__main__":
    username, password, interval = parse_args()
    if interval:
        session = requests.Session()
        try:
            while True:
                time.sleep(0.0001)  # to prevent cpu usage and cause some artificial drift
                print(login_user(username, make_password_ready(password), session=session))
                time.sleep(interval)
        except KeyboardInterrupt:
            print("KeyboardInterrupt received, exiting...")
        sys.exit(0)
    print(login_user(username, make_password_ready(password)))
