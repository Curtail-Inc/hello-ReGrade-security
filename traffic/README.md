# Traffic — the "point your existing tests at ReGrade" step

`test_api.py` is a normal functional test suite. It asserts CRUD behavior and makes
**no security assertions** — it never checks whether `password` leaks.

Run it against the app directly:

    python -m pytest traffic/test_api.py            # boots an in-process instance
    BASE_URL=http://localhost:8001 pytest traffic/test_api.py   # against instance-a

**To record with ReGrade, change one thing** — point `BASE_URL` at the sensor proxy:

    BASE_URL=http://localhost:<proxy-port> pytest traffic/test_api.py

The tests still pass. ReGrade records the traffic. Nothing about the suite changed.
