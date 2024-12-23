Remote was far and slow and the challenge had a timeout (60 seconds) so I made 2 exploits:
- the first one is meant to be run locally
- the second one is ugly but it doesn't use recvuntil to make it faster for the remote (put everything in a payload and io.send everything at once)