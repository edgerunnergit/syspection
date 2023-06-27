# Rust Network Scanner

This is a Rust project that implements a network scanner using the XDP (eXpress Data Path) technology in the Linux kernel. The scanner uses XDP programs to intercept and analyze network packets at the driver layer, allowing for high-performance packet processing.

## Getting Started

To build and run the network scanner, you will need Rust and Cargo installed on your system. You can install Rust and Cargo by following the instructions on the official Rust website. Another prerequisite is the bpf-linker tool, which is used to build the XDP programs. You can install bpf-linker by running the following command:

Once you have Rust and Cargo installed, you can build the network scanner by running the following command in the project directory:

```bash
cargo install bpf-linker
```

### Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

### Build Userspace

```bash
cargo build
```

This will build the network scanner in release mode, which will optimize the code for performance.

### Run

```bash
RUST_LOG=info cargo xtask run -- -iface eth0
```

Here, you need to replace `eth0` with the name of the network interface you want to scan. You can find the name of your network interfaces by running the `ip link` command.

## Contributing

If you would like to contribute to the network scanner, please open an issue or pull request on the GitHub repository. We welcome contributions of all kinds, including bug reports, feature requests, and code contributions.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
