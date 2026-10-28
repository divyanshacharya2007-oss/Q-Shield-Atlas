"""Generate the default synthetic toy capture artifact."""

from .service import create_capture, dump_capture


def main() -> None:
    capture = create_capture()
    path = dump_capture(capture, "contracts/capture.json")
    print(f"Wrote labeled toy capture: {path}")


if __name__ == "__main__":
    main()