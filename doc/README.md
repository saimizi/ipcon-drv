# IPC Over Netlink (IPCON) driver I/F

IPCON (IPC Over Netlink) is an IPC for user applications based on the Netlink
protocol. It is implemented as a sub protocol family of the generic netlink
subsytem. This document describes the driver I/F of IPCON.

## Outline of IPCON

This section describes the outline of IPCON driver. The following figure shows
the software stack of IPCON:

 
![ipcon_stack](/ipcon_stack.png)


As described in software stack, IPCON driver which is a generic netlink driver
intermidated between the user processes that want to communicate with each other.

### Peer
The entity used to transfer messages is called a ***Peer***. A peer must have
following attributes:

1. *name*  
   A string to identify the peer. *name* must be unique in the system with a
   maxmum length of 64 byte.

2. *control port*  
   A netlink socket used to send messages and communicate to IPCON driver.

3. *communicate port*  
   A netlink socket used to receive messages.

4. *peer type*  
   The type of the peer, which is defined as "enum peer_type". the type of a
   peer must be one of the following:  
   * *ANON*  
     A peer used to send/receive message to/from another peer. An *ANON* peer
     does not have a group and can not send multicast messages. Also the
     creation and exit of an *ANON* peer will not be informed to the user
     proceses.

   * *PUBLISHER*  
     A peer used to send group messages. A *PUBLISHER* may have one or more
     multicast groups which can be suscribed by other peers. The messages sent
     to the group will be multicasted to all the suscribers. A *PUBLISHER* can
     not receive messages from other peers.

   * *SERVICE*  
     Same to *ANON* peer, but the creation and exit of a *SERVICE* peer will be
     informed to user processes though the IPCON kernel event.

   * *SERVICE_PUBLISHER*  
     A peer can act both as a "PUBLISHER" and a "SERVICE".

### Message transfer

In IPCON, messages from a peer to another peer are ALWAYS intermediated by the
IPCON driver. That means:

* Peers identify each other by using *name* instead of the netlink port.  
  The port number of a peer will never be exposed to other peers by IPCON.

* When a peer wants to send a message to another peer,  
  1. Sender peer passes the message and the name of the target peer to IPCON
     driver though the *control port*;
  2. IPCON driver checks the message and sender/target peer;
  3. If both the sender/target peer and  the message are valid, IPCON driver
     passes the message to the *communicate port* of the target peer together
     with the name of the sender peer;

* A "PUBLISHER" or "SERVICE_PUBLISHER" peer may create one or more groups. When
  it wants to send a group message,
  1. It passes the message and the group name to IPCON driver though *control
     port*;
  2. IPCON driver checks the message, sender peer and group name;
  3. If the check succeed, it multicasts the message to all suscribers's
     communicate port together the name of the sender peer and the group.

Since messages are transferred by using netlink protocol which is not a reliable
one, messages may be dropped because of the buffer flow of the receving peer.


### IPCON Kevent

IPCON driver manages all peers in the system that is using IPCON and it
maintains a speicial "*ipcon_kevent*" message group to inform the suscribers the
creation and exit of a peer (except an *ANON* peer). The message to this
*ipcon_kevent* group is defined as following:

```
enum ipcon_kevent_type {
	IPCON_EVENT_PEER_ADD,
	IPCON_EVENT_PEER_REMOVE,
	IPCON_EVENT_GRP_ADD,
	IPCON_EVENT_GRP_REMOVE,
};

struct ipcon_kevent {
	enum ipcon_kevent_type type;
	union {
		struct {
			char name[IPCON_MAX_NAME_LEN];
			char peer_name[IPCON_MAX_NAME_LEN];
		} group;
		struct {
			char name[IPCON_MAX_NAME_LEN];
		} peer;
	};
};
```

The following summarize the message speicifcation.

* IPCON_EVENT_PEER_ADD   
  A new peer is added.  
  * peer.name  
    Name of the peer newly added. 


* IPCON_EVENT_PEER_REMOVE  
  A peer is removed.  
  * peer.name  
    Name of the peer removed.


* IPCON_EVENT_GRP_ADD    
  A new group is added.
  * group.name  
    Name of the goroup newly added.
  * group.peer_name
    Name of the peer to which the group belongs.


* IPCON_EVENT_GRP_REMOVE  
  A group is removed.
  * group.name  
    Name of the goroup removed.
  * group.peer_name
    Name of the peer to which the removed group belongs.
