# todo list

1. implement modern / bungeecord / none forwarding
2. support haproxy integration from trusted proxies
3. inject mfp credential in connection?
4. login brute-force protection: the 3-try limit in `initiateLoginFlow` is
   per-connection and trivially bypassed by reconnecting. Add real rate
   limiting (per-IP / per-account), backoff between attempts, and reject
   empty/weak passwords at registration.