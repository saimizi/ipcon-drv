# IPCON Driver

## Overview

IPCON (IPC Over Netlink) is a Linux kernel driver that provides an Inter-Process Communication (IPC) mechanism for user-space applications. It is implemented as a generic Netlink protocol family, enabling communication between different processes on the same system.

## Features

*   **Peer-to-Peer Communication:** Allows direct communication between named peers.
*   **Publish-Subscribe Model:** Supports group messaging for one-to-many communication.
*   **Service Discovery:** Notifies applications about the creation and removal of services.
*   **Netlink-Based:** Leverages the existing Netlink infrastructure in the Linux kernel.

## Building the Driver

To build the IPCON driver, you need to have the Linux kernel source tree and a configured build environment.

1.  **Configure the kernel:**
    Enable the `IPCON` option in the kernel configuration (`make menuconfig`). You can find it under "General setup" -> "IPC Over Netlink(IPCON)".

2.  **Build the driver:**
    The driver will be built as part of the kernel build process. The following modules will be compiled:
    *   `main.o`
    *   `ipcon_nl.o`
    *   `ipcon_msg.o`
    *   `ipcon_db.o`
    *   `name_cache.o`
    *   `ipcon_debugfs.o` (if `CONFIG_DEBUG_FS` is enabled)

## Usage

For detailed information on how to use the IPCON driver, please refer to the [documentation](doc/README.md).
