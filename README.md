# portal

A minecraft server that authenticate player and transfer them to destination servers with temporary access, no traffic
proxied.  
It can also act as a replacement of SRV record, since it redirects by requested hostname.

# Features

- **Online/Offline Hybrid Authentication**  
  Portal sniffs UUID to distinguish online players, challenge them with Yggdrasil then transfer to destination
  immediately. For offline
  players, they will join the simulated server where password authentication will be used.
- **High performance, actually.**  
  The server stands on basic packet serializers, throwing bloated codes away thus you don't pay anything unwanted. Also, we benefit from
  the asynchronous goroutine which made our code efficient in I/O, Memory and easy to maintain.
- **Unified secure authentication**  
  servers, especially the offline or modded ones, often suffer issues like improperly secured authentication and identity synchronization. By deploying such gateway, you need only one account to access all the servers even in the federation one.      