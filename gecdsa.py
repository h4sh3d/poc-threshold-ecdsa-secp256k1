#!/usr/bin/env python
import hashlib
import paillier
import ecdsa
import utils


if __name__ == "__main__":
    print("G-ECDSA")
    # Aclice
    # ...

    # Bob
    # ...

    # Carol
    # ...

    # Message to sign
    message = "hello"
    h = hashlib.sha256()
    h.update(message.encode("utf-8"))
    m = long(h.hexdigest(), 16)
