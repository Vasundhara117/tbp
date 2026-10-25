
import argparse
import json
import time
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_URL = "http://127.0.0.1:8000/api/v1/messages"
DEFAULT_DEVICE_ID = "CCTV-ESP32-01"
DEVICE_TYPE = "cctv_simulator"


def send_message(server_url, device_id, message_number):
    timestamp_ms = int(time.time() * 1000)

    payload = {
        "device_id": device_id,
        "device_type": DEVICE_TYPE,
        "message_id": f"msg-{message_number:04d}-{uuid.uuid4().hex[:6]}",
        "timestamp_ms": timestamp_ms,
        "data": {
            "status": "online",
            "activity": "heartbeat"
        }
    }

    request = Request(
        server_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urlopen(request, timeout=5) as response:
            result = response.read().decode("utf-8")
            print(f"HTTP {response.status} | {json.dumps(payload)}")
            if result:
                print(f"Backend: {result}")

    except HTTPError as error:
        print(f"HTTP {error.code}: {error.read().decode('utf-8')}")
    except (URLError, TimeoutError) as error:
        print(f"Connection failed: {error}")


def main():
    parser = argparse.ArgumentParser(
        description="SecureIoT Sentinel device simulator"
    )
    parser.add_argument("--url", default=DEFAULT_URL,
                        help="Backend message endpoint URL")
    parser.add_argument("--device-id", default=DEFAULT_DEVICE_ID,
                        help="Device ID to send")
    parser.add_argument("--mode", choices=["normal", "burst"],
                        default="normal")
    parser.add_argument("--duration", type=int, default=10,
                        help="Duration in seconds; burst mode defaults to 10")
    args = parser.parse_args()

    if args.duration < 1:
        parser.error("--duration must be at least 1 second")

    interval = 5.0 if args.mode == "normal" else 0.2
    deadline = time.monotonic() + args.duration
    message_number = 0

    print(f"Mode: {args.mode.upper()}")
    print(f"Device ID: {args.device_id}")
    print(f"Endpoint: {args.url}")

    while time.monotonic() < deadline:
        message_number += 1
        send_message(args.url, args.device_id, message_number)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(interval, remaining))

    print(f"Simulation complete. Messages attempted: {message_number}")


if __name__ == "__main__":
    main()
