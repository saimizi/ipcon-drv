# IPCON Driver Testing Guide

This document describes how to use the IPCON test tool to build and test the IPCON kernel driver in a virtual machine environment.

## Overview

The IPCON driver cannot be built as a loadable module because it uses internal kernel netlink functions. Therefore, it must be built into the kernel. This test tool automates the process of:

1. Building a Linux kernel with IPCON driver built-in
2. Creating a minimal rootfs with busybox automatically configured for IPCON testing
3. Launching a QEMU virtual machine for testing

The tool handles all configuration automatically, requiring no manual intervention during the build process.

## Prerequisites

### Required Packages

Install the following packages on your system:

**Ubuntu/Debian:**
```bash
sudo apt install build-essential libncurses-dev bison flex libssl-dev libelf-dev \
                 qemu-system-x86 bc python3 wget cpio gzip
```

**CentOS/RHEL/Fedora:**
```bash
sudo yum install gcc make ncurses-devel bison flex openssl-devel elfutils-libelf-devel \
                 qemu-kvm bc python3 wget cpio gzip
```

### Optional (for KVM acceleration)

```bash
# Ubuntu/Debian
sudo apt install qemu-kvm

# CentOS/RHEL/Fedora
sudo yum install qemu-kvm
```

## Usage

The test tool provides several commands that can be used individually or together.

### Command Line Interface

```bash
./ipcon-test-tool [OPTIONS] COMMAND [COMMAND_OPTIONS]
```

### Available Commands

#### 1. Build Kernel (`build-kernel`)

Build a Linux kernel with IPCON driver built-in:

```bash
# Build latest stable kernel
./ipcon-test-tool build-kernel

# Build specific kernel version
./ipcon-test-tool build-kernel --version 6.6.65

# Generate config only (useful for customization)
./ipcon-test-tool build-kernel --config-only
```

**Options:**
- `--version VERSION`: Specify kernel version (default: latest stable)
- `--config-only`: Only generate kernel configuration, don't build

#### 2. Build Rootfs (`build-rootfs`)

Create a minimal root filesystem with busybox configured automatically for IPCON testing:

```bash
# Build with default busybox version (1.36.1 - stable)
./ipcon-test-tool build-rootfs

# Build with specific busybox version
./ipcon-test-tool build-rootfs --version 1.36.1

# Use latest version (may have build issues)
./ipcon-test-tool build-rootfs --version 1.37.0
```

**Options:**
- `--version VERSION`: Specify busybox version

**Note:** Busybox is automatically configured with essential networking tools and utilities needed for IPCON driver testing. No manual configuration is required.

#### 3. Run Virtual Machine (`run-vm`)

Launch QEMU virtual machine with the built kernel and rootfs:

```bash
# Run VM with default settings
./ipcon-test-tool run-vm

# Run with specific kernel version and more memory
./ipcon-test-tool run-vm --kernel-version 6.6.65 --memory 1G

# Run without KVM acceleration
./ipcon-test-tool run-vm --no-kvm
```

**Options:**
- `--kernel-version VERSION`: Specify kernel version to use
- `--memory SIZE`: VM memory size (default: 512M)
- `--no-kvm`: Disable KVM acceleration

#### 4. All-in-One (`all`)

Build kernel, rootfs, and run VM in one command:

```bash
# Build everything and run VM
./ipcon-test-tool all

# With custom versions and settings
./ipcon-test-tool all --kernel-version 6.6.65 --busybox-version 1.36.1 --memory 1G
```

#### 5. Clean (`clean`)

Remove build artifacts while preserving downloaded source packages for faster rebuilds:

```bash
# Remove all build artifacts but keep downloaded packages (default)
./ipcon-test-tool clean

# Remove only kernel build artifacts
./ipcon-test-tool clean --kernel

# Remove only rootfs build artifacts  
./ipcon-test-tool clean --rootfs

# Remove only output files (kernel image, initramfs)
./ipcon-test-tool clean --output

# Combine options
./ipcon-test-tool clean --kernel --rootfs
```

**Options:**
- `--kernel`: Remove kernel build artifacts (preserves downloaded kernel source)
- `--rootfs`: Remove rootfs build artifacts (preserves downloaded busybox source)
- `--output`: Remove only final output files (vmlinuz-*, initramfs.*)

#### 6. Clean All (`cleanall`)

Remove everything including downloaded source packages:

```bash
# Remove all build artifacts AND downloaded packages
./ipcon-test-tool cleanall
```

**What gets cleaned:**

| Command | Removes | Preserves |
|---------|---------|-----------|
| `clean` (default) | Build artifacts, object files, configs, output files | Downloaded kernel & busybox source packages |
| `clean --kernel` | Kernel build artifacts only | Downloaded kernel source, busybox artifacts |
| `clean --rootfs` | Rootfs and busybox build artifacts | Downloaded packages, kernel artifacts |  
| `clean --output` | Final kernel images and initramfs files | Everything else |
| `cleanall` | Everything in `ipcon-test-build/` directory | Nothing |

**Benefits:**
- `clean`: Fast rebuilds since sources don't need to be downloaded again
- `cleanall`: Complete cleanup when you want to start fresh or free maximum disk space

### Global Options

- `-v, --verbose`: Enable verbose logging

## Directory Structure

The tool creates the following directory structure:

```
ipcon-test-build/
├── linux/              # Linux kernel source
├── busybox/            # Busybox source
├── rootfs/             # Root filesystem
└── output/             # Build outputs
    ├── vmlinuz-X.X.X   # Kernel image
    └── initramfs.cpio.gz # Root filesystem archive
```

## Testing IPCON Driver

Once the VM is running, you can test the IPCON driver:

### 1. Check Driver Status

```bash
# Check if IPCON driver loaded successfully
dmesg | grep ipcon

# Expected output:
# ipcon: init successfully.
```

### 2. Check Kernel Configuration

```bash
# Verify IPCON is built-in
grep IPCON /proc/config.gz | zcat
# Should show: CONFIG_IPCON=y
```

### 3. Test Netlink Interface

The IPCON driver creates a netlink socket interface. You can test it by:

```bash
# Check available netlink families
cat /proc/net/netlink

# Look for IPCON-related entries in kernel logs
dmesg | grep -i netlink
```

### 4. Debug Information (if CONFIG_DEBUG_FS is enabled)

```bash
# Check debug filesystem
ls /sys/kernel/debug/

# IPCON debug info (if available)
ls /sys/kernel/debug/ipcon/
```

## Exiting the VM

To exit the QEMU virtual machine:

1. Press `Ctrl+A` then `X` (QEMU monitor)
2. Or use the `poweroff` command inside the VM

## Troubleshooting

### Build Issues

**Missing dependencies:**
```bash
# Install missing build tools
sudo apt install build-essential libncurses-dev bison flex libssl-dev
```

**Kernel build fails:**
- Check available disk space (kernel builds require ~10GB)
- Verify all dependencies are installed
- Try with `--config-only` first to check configuration

**Download failures:**
- Check internet connection
- Some corporate networks may block direct downloads

### VM Issues

**QEMU not found:**
```bash
# Install QEMU
sudo apt install qemu-system-x86
```

**KVM not available:**
- Use `--no-kvm` flag
- Install KVM support: `sudo apt install qemu-kvm`
- Add user to kvm group: `sudo usermod -a -G kvm $USER`

**VM doesn't boot:**
- Check kernel and initramfs files exist in `ipcon-test-build/output/`
- Try increasing memory with `--memory 1G`

### Driver Issues

**IPCON driver not loaded:**
- Check kernel config includes `CONFIG_IPCON=y`
- Verify all IPCON source files were copied
- Check for compilation errors in build logs

**Netlink interface not working:**
- Ensure `CONFIG_NETLINK_DIAG=y` is set
- Check kernel has networking support enabled

## Advanced Usage

### Custom Kernel Configuration

1. Generate config only:
   ```bash
   ./ipcon-test-tool build-kernel --config-only
   ```

2. Customize the configuration:
   ```bash
   cd ipcon-test-build/linux
   make menuconfig
   ```

3. Build with custom config:
   ```bash
   ./ipcon-test-tool build-kernel
   ```

### Development Workflow

For IPCON driver development:

1. Make changes to IPCON source files
2. Rebuild kernel: `./ipcon-test-tool build-kernel`
3. Test in VM: `./ipcon-test-tool run-vm`

### CI/CD Integration

The tool can be used in automated testing:

```bash
#!/bin/bash
set -e

# Build and test
./ipcon-test-tool build-kernel --version 6.6.65
./ipcon-test-tool build-rootfs
# Add automated tests here
```

## Examples

### Quick Test

```bash
# Quick test with latest versions
./ipcon-test-tool all
```

### Specific Versions

```bash
# Test with specific kernel version
./ipcon-test-tool build-kernel --version 6.1.69
./ipcon-test-tool build-rootfs --version 1.35.0
./ipcon-test-tool run-vm --kernel-version 6.1.69 --memory 1G
```

### Development Testing

```bash
# After making IPCON driver changes
./ipcon-test-tool clean
./ipcon-test-tool all --verbose
```

## Performance Notes

- **Build Time**: Kernel compilation takes 10-30 minutes depending on hardware
- **Disk Space**: Requires ~15GB free space for complete build
- **Memory**: VM runs fine with 512MB, but 1GB recommended for testing
- **KVM**: Enables much faster VM performance when available

## Contributing

When contributing to the IPCON driver:

1. Test changes with multiple kernel versions
2. Verify both debug and release builds work
3. Test in VM environment before submitting changes
4. Update this documentation if adding new features

## Support

For issues with the test tool:
1. Check troubleshooting section above
2. Run with `--verbose` flag for detailed logs
3. Verify all prerequisites are installed
4. Check available disk space and memory