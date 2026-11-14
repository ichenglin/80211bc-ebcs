## Setup Environment

Setup python virtual environment and install dependencies:
```bash
sudo bin/init.sh
source .venv/bin/activate
```

Copy and populate the `.env` file with your configuration:
```bash
cp .env.example .env
```

## Monitor Mode

Monitor mode disables the association requirement entirely, and allows the wireless interface to listen and inject raw frames directly onto the radio frequency channel. Both the interfaces used by the device and station should be configured in monitor mode.

Check available wireless interfaces:
```bash
iw dev
```

Adjust the interface mode and channel:
```bash
sudo bin/intf.sh -i <interface> [-m <monitor|managed>] [-c <channel>]
```

## Run Device/Station

```bash
sudo .venv/bin/python -m <src.device|src.station|src.destination>
```

## Wireshark Monitoring

Filter packets by action value:

```text
wlan.fixed.publicact == <0x33|0x34|0x35>
```