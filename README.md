# portal

A minecraft server that authenticate players and transfer them to destinated servers with temporary access, no traffic
proxied.  
It can also act as a replacement of SRV record, since it handle redirections by requested hostname.

# Features

- **Online/Offline Hybrid Authentication**  
  Portal sniffs UUID to distinguish online players and challenges them with Yggdrasil . Once the identity is known, they will be transferred to the destination
  immediately. For offline players, it offers the traditional user/pass authentication. Additionally, It can be used to accept offline players for your online servers without affecting online players (UUID changes, etc.). Moreover, online players can log in their account by user/pass when they can't connect to Mojang. 
  players, they will join the simulated server where password authentication will be used.
- **High performance & lightweight usage.**  
  What does the server do is mostly copying data back and forth. It is written from scratch without bloated codes thus you pay nothing unwanted. Also, since it has written in the blazingly 🚀 fast golang, I/O operations are scheduled efficiently and have sufficient performance for common usages. We have also considered DDoS in development, and the server should not perform badly even in stress testing.  
- **Decentralization**  
  You can set multiple portal instance for lower latency, or hide them behind firewalls, grant access to players manuly. portals are decentralized, you can even join servers without a portal server but a valid signed token.
- **Unified secure authentication**  
  By deploying the gateway, you need only one account to access all the servers without redundant registration (especially temporary servers like modpack term). Since our authentication performs
  in early-login stage, it is unlikely to be bypassed by unknown mod "glitches" that grant player access before they logged in. In fact, these kinds of bugs are common in plugin/mods hybrid servers
  becuz mods have no knowledge of the existence of authentication mods.
