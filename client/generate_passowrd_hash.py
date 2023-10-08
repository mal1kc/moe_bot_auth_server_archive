def parse_args() -> str:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("password", type=str, help="password to hash")
    args = parser.parse_args()
    return args.password


def main():
    args = parse_args()
    from encryption import make_password_hash

    print(make_password_hash(args))


if __name__ == "__main__":
    main()
