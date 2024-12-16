# Resoy

![out](https://github.com/user-attachments/assets/e5a09480-e1b2-4c17-a0f0-fa760407e2ce)
Resoy is a small command-line tool for performing DNS queries. It allows you to resolve domain names and retrieve various DNS record types.
## Installation

To install Resoy, you need to have Rust and Cargo installed. Just type:

```sh
cargo install --git https://github.com/1ort/resoy.git
```

## Usage

```sh
# Basic Usage
resoy example.com

# Query Multiple Record Types
resoy example.com A AAAA NS CNAME

# Specify a Custom DNS Server
resoy --server 8.8.8.8:53 example.com A AAAA
```

## Options

- `-s, --server <SERVER>`: Specify the DNS server to use (default: `1.1.1.1:53`).
- `-h, --help`: Print the help message.
- `-V, --version`: Print the version of Resoy.

## Example

```sh
❯ resoy example.com A AAAA NS
 AAAA example.com.       44m13s 2606:2800:21f:cb07:6820:80da:af6b:8b2c
    A example.com.       38m35s 93.184.215.14
   NS example.com.    22h20m11s a.iana-servers.net.
   NS example.com.    22h20m11s b.iana-servers.net.
```
