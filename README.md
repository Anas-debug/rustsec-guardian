# dep-sense

dep-sense is a Supply Chain Intelligence Platform for Rust, providing dependency analysis and security scanning capabilities.

## Installation

```sh
git clone https://github.com/yourusername/dep-sense.git
cd dep-sense
cargo build --release
```

## Usage

```sh
dep-sense [OPTIONS]
```

### Options

- `-m, --manifest-path <MANIFEST_PATH>`: Path to Cargo.toml (default: Cargo.toml)
- `-o, --output <OUTPUT>`: Output format (text, json) (default: text)
- `--deep`: Enable deep scanning

## License

This project is licensed under the MIT License.
