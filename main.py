from app.server import Server


def main():
    try:
        Server().run()
    except Exception:
        pass


if __name__ == "__main__":
    main()
