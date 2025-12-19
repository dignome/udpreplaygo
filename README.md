Simulates an NS2 / Natural Selection 2 game server by sheer brute force.

-Waits for the client side packets to hit and then sends the next packet.
-Attempts to replay at same rate as captured by packet timings.

Once started you can connect your NS2 client to the simulated server more easier by making a shortcut.
URL=steam://run/4920//+connect myserverip:27005

For the network capture be sure to strip out everything before until the first SPARKNET packet from the client.

A few gotchas - may have to run the playback more than once to get it to start.  Does not currently handle map changes.
