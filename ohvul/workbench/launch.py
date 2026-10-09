import argparse
import socket
import uvicorn


def main():
    parser = argparse.ArgumentParser(description="WildTrace local workbench")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--data-dir")
    args = parser.parse_args()
    from .app import create_app

    # Keep the socket reserved until handed to uvicorn, avoiding a port race.
    listener = socket.socket()
    try:
        listener.bind(("127.0.0.1", args.port))
    except OSError:
        listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.listen(128)
    print(f"WildTrace: http://127.0.0.1:{port}", flush=True)
    server = uvicorn.Server(uvicorn.Config(create_app(args.data_dir), log_level="info"))
    server.run(sockets=[listener])


if __name__ == "__main__":
    main()
