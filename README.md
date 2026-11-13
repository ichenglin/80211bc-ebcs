## Setup Environment

```bash
sudo bin/init.sh
source .venv/bin/activate
```

## Monitor Mode

Monitor mode disables the association requirement entirely, and allows the wireless interface to listen/inject raw 802.11 frames directly onto the radio frequency channel.

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
.venv/bin/python -m <src.device|src.station>
```