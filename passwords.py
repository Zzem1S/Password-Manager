from lib.client import Client
import argparse

def parse_args():
    """Parses arguments from command line
    """
    parser = argparse.ArgumentParser(description='Run password manager')
    parser.add_argument('host', type=str, help='Host')
    parser.add_argument('port', type=int, help='Port')
    parser.add_argument('username', type=str, help='Username')
    parser.add_argument('master_password', type=str, help='Master password')
    parser.add_argument('command', type=str, help='Command: [getpasswords, addpassword]')
    parser.add_argument('kwargs', nargs='*', type=str, help='Password name and Password value to add')
    return parser.parse_args()

def main():
    args = parse_args()
    client = Client(f"http://{args.host}:{args.port}")
    if args.command == "getpasswords":
        print(client.get_passwords(args.username, args.master_password))
    elif args.command == "addpassword":
        print(client.add_password(args.username, args.master_password, args.kwargs[0], args.kwargs[1]))
    else:
        print("Unknown command")


if __name__ == "__main__":
    main()