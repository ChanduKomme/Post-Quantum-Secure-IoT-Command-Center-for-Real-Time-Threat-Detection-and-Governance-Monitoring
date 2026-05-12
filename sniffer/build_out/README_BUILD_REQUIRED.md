# Build output intentionally not committed

This folder is intentionally empty in the cleaned source package.

Reasons:
- Old binaries may contain stale build-time constants such as previous Splunk HEC tokens.
- Old intermediate files contained local workstation paths.
- Rebuilding from sanitized source is required before flashing hardware.

Build from the project root with:

```bash
bash tools/build_firmware.sh --role sniffer
```

For all roles:

```bash
bash tools/build_firmware.sh --all
```
