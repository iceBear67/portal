# portal

A minecraft server that authenticate player and transfer them to destination servers with temporary access, no traffic
proxied.  
It can also act as a replacement of SRV record, since it redirects by requested hostname.

# Features

- **Online/Offline Hybrid Authentication**  
  Portal sniffs UUID to distinguish online players, challenge them with Yggdrasil then transfer to destination
  immediately. For offline players, it also offers traditional user/pass authentication. Additionally, It can be used to accept offline players for your online servers while online players aren't affected at all (UUID changes, etc.). Moreover, online players can log in their account by user/pass when they can't connect Mojang. 
  players, they will join the simulated server where password authentication will be used.
- **High performance with lightweight usage.**  
  The server does mostly copy data back and forth, without bloated codes thus you pay nothing unwanted. Also, since we're written in the blazingly 🚀 fast golang, I/O operations are scheduled efficiently and have sufficient performance for common usages. We have also considered DDoS in development, and the server should not perform badly even in stress testing.  
- **Decentralization**  
  You can set multiple portal instance for faster access, or hide them behind firewalls, grant access to players by yourself. The way portal authenticate player is decentralized, you're free to join servers without portal but a valid signed token.
- **Unified secure authentication**  
  By deploying the gateway, you need only one account to access all the servers without repeated registration (especially activity servers like modpack term). Also, since our authentication performs
  in early-login stage, it is unlikely to be bypassed by unknown mod "glitches" that grant player access before they logged in. In fact, these kinds of bugs are common in plugin/mods hybrid servers
  since mods have no knowledge of the existence of authentication mods.