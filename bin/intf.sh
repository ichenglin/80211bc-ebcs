#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Please run with sudo: sudo $0 -i <interface> [-m <monitor|managed>] [-c <channel>]"
  exit 1
fi

usage() {
  echo "Usage: sudo $0 -i <interface> [-m <monitor|managed>] [-c <channel>]"
  echo ""
  echo "Available wireless interfaces:"
  iw dev | awk '$1=="Interface"{print " - " $2}'
  exit 1
}

while getopts "i:m:c:h" opt; do
  case "$opt" in
    i) IFACE="$OPTARG" ;;
    m) MODE="$OPTARG" ;;
    c) CHANNEL="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

if [ -z "$IFACE" ]; then
  echo "Error: Interface (-i) is required."
  usage
fi

if ! ip link show "$IFACE" > /dev/null 2>&1; then
  echo "Error: Interface '$IFACE' does not exist."
  exit 1
fi

if [ -n "$MODE" ]; then
  if [[ "$MODE" != "monitor" && "$MODE" != "managed" ]]; then
    echo "Error: Mode must be 'monitor' or 'managed'."
    exit 1
  fi

  ip link set "$IFACE" down
  iw dev "$IFACE" set type "$MODE"
  ip link set "$IFACE" up
fi

if [ -n "$CHANNEL" ]; then
  iw dev "$IFACE" set channel "$CHANNEL"
fi

iw "$IFACE" info