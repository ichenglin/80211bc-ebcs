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

Monitor mode disables the association requirement entirely, and allows the wireless interface to listen and inject raw frames directly onto the radio frequency channel. Both device and station interfaces should be configured to monitor mode and the same channel.

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

## References

Over-the-air MAC specification:
- [802.11-2024](https://ieeexplore.ieee.org/document/10979691)
- [802.11bc-2023](https://ieeexplore.ieee.org/document/10456575)

Architectural concept of appending location metadata is inspired by the patent:
- [WO2022232740](https://patentscope.wipo.int/search/en/detail.jsf?docId=WO2022232740)
