# IPCON Driver Interface

IPCON (IPC Over Netlink) is a kernel module that provides an Inter-Process Communication (IPC) mechanism for user-space applications. It is implemented as a generic Netlink protocol family. This document describes the driver's application programming interface (API).

## IPCON Overview

The IPCON driver acts as an intermediary for user processes, enabling them to communicate with each other. The following diagram illustrates the software stack of IPCON:

![IPCON Stack](doc/ipcon_stack.png)

### Peers

A **Peer** is an entity used to transfer messages. Each peer has the following attributes:

1.  **Name**: A unique string of up to 63 characters used to identify the peer.
2.  **Control Port**: A Netlink socket for sending messages and communicating with the IPCON driver.
3.  **Communication Port**: A Netlink socket for receiving messages.
4.  **Peer Type**: The type of the peer, which can be one of the following:
    *   **ANON**: A peer for sending and receiving messages to and from other peers. `ANON` peers do not have groups and cannot send multicast messages. The creation and exit of `ANON` peers are not broadcast to other peers.
    *   **PUBLISHER**: A peer for sending group messages. A `PUBLISHER` can have one or more multicast groups that other peers can subscribe to. Messages sent to a group are multicasted to all subscribers. `PUBLISHER` peers cannot receive messages.
    *   **SERVICE**: Similar to an `ANON` peer, but the creation and exit of a `SERVICE` peer are broadcast to other peers through IPCON kernel events.
    *   **SERVICE_PUBLISHER**: A peer that can act as both a `PUBLISHER` and a `SERVICE`.

### Message Transfer

Messages between peers are always intermediated by the IPCON driver:

*   Peers identify each other by name, not by Netlink port. The port number of a peer is never exposed to other peers by IPCON.

*   When a peer sends a message to another peer:
    1.  The sender passes the message and the target peer's name to the IPCON driver through the control port.
    2.  The IPCON driver validates the message and the sender/target peers.
    3.  If valid, the IPCON driver passes the message to the target peer's communication port, along with the sender's name.

*   When a `PUBLISHER` or `SERVICE_PUBLISHER` sends a group message:
    1.  The sender passes the message and the group name to the IPCON driver through the control port.
    2.  The IPCON driver validates the message, sender, and group name.
    3.  If valid, the IPCON driver multicasts the message to all subscribers' communication ports, along with the sender's name and the group name.

**Note:** Messages are transferred using the Netlink protocol, which is not reliable. Messages may be dropped if a receiving peer's buffer overflows.

### IPCON Kernel Events

The IPCON driver manages all peers in the system and uses a special `ipcon_kevent` message group to notify subscribers about the creation and exit of peers (excluding `ANON` peers).

The `ipcon_kevent` message is defined as follows:

```c
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

The following describes the message specifications:

*   **IPCON_EVENT_PEER_ADD**: A new peer has been added.
    *   `peer.name`: The name of the newly added peer.

*   **IPCON_EVENT_PEER_REMOVE**: A peer has been removed.
    *   `peer.name`: The name of the removed peer.

*   **IPCON_EVENT_GRP_ADD**: A new group has been added.
    *   `group.name`: The name of the newly added group.
    *   `group.peer_name`: The name of the peer to which the group belongs.

*   **IPCON_EVENT_GRP_REMOVE**: A group has been removed.
    *   `group.name`: The name of the removed group.
    *   `group.peer_name`: The name of the peer to which the removed group belongs.
