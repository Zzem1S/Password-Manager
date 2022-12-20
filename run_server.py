from lib.server import Server
import argparse

def parse_args():
    """Parses arguments from command line
    """
    parser = argparse.ArgumentParser(description='Run server')
    parser.add_argument('host', type=str, help='Host')
    parser.add_argument('port', type=int, help='Port')
    return parser.parse_args()

def main():
    args = parse_args()
    server = Server(args.host, args.port)
    server.start()

if __name__ == "__main__":
    main()