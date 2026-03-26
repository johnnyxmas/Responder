#!/usr/bin/env bash
# Responder launcher for macOS

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USAGE="$(basename "$0") [Responder.py arguments...] - Script to automagically re/configure a macOS environment and launch Responder"

# Environment check
if [[ "$(uname -s)" != "Darwin" ]]; then
	echo "This script is only for macOS. On any other OS, run Responder.py directly."
	exit 1
elif [[ $# -eq 0 ]]; then
	echo "Usage: $USAGE"
	echo "You haven't provided any arguments! Run Responder.py -h for args help."
	exit 1
elif [[ "$EUID" -ne 0 ]]; then
	echo "Managing services requires root privileges. Please run as root."
	exit 1
fi

# All ports Responder can bind to (must stay in sync with Responder.py main())
TCP_LIST=(21 25 53 80 88 110 135 139 143 389 443 445 587 636 993 1433 1883 3128 3389 5985 5986)
UDP_LIST=(53 88 137 138 161 389 547 1434 5353 5355)

# Known macOS daemons that conflict with Responder
KNOWN_DAEMONS=(
	com.apple.Kerberos.kdc
	com.apple.mDNSResponder
	com.apple.mDNSResponderHelper
	com.apple.srp-mdns-proxy
	com.apple.smbd
	com.apple.netbiosd
)

SVC_LIST=()

# Restore services on any exit (normal, error, or signal)
restore_services() {
	if [[ ${#SVC_LIST[@]} -gt 0 ]]; then
		echo ""
		echo "Restoring stopped services..."
		for AGENT in "${SVC_LIST[@]}"; do
			echo "  Restarting: $AGENT"
			launchctl bootstrap system /System/Library/LaunchDaemons/"$AGENT".plist 2>/dev/null || true
		done
	fi
}
trap restore_services EXIT

# Auto-detect local IP from interface if -i not provided
# Parses -I <iface> from args, then checks if -i is present
AUTO_IP=""
IFACE=""
HAS_IP_FLAG=false
ARGS=("$@")
for ((i=0; i<${#ARGS[@]}; i++)); do
	case "${ARGS[$i]}" in
		-I|--interface)
			IFACE="${ARGS[$((i+1))]:-}"
			;;
		-i|--ip)
			HAS_IP_FLAG=true
			;;
	esac
done

if [[ "$HAS_IP_FLAG" = false && -n "$IFACE" && "$IFACE" != "ALL" ]]; then
	AUTO_IP=$(ipconfig getifaddr "$IFACE" 2>/dev/null || true)
	if [[ -n "$AUTO_IP" ]]; then
		echo "Auto-detected IP $AUTO_IP on $IFACE (use -i to override)"
		set -- "$@" -i "$AUTO_IP"
	else
		echo "WARNING: Could not detect IP for $IFACE. You may need to pass -i manually."
	fi
fi

# Check SIP status
echo "Checking System Integrity Protection status..."
if csrutil status 2>/dev/null | grep -qw enabled; then
	echo "==========================================================================="
	echo "WARNING: System Integrity Protection (SIP) is ENABLED"
	echo ""
	echo "With SIP enabled, this script cannot automatically stop macOS services"
	echo "that may conflict with Responder (SMB, mDNSResponder, Kerberos, NetBIOS)."
	echo ""
	echo "You have three options:"
	echo "1. Disable SIP (see README for instructions) for full functionality"
	echo "2. Manually stop conflicting services before running Responder"
	echo "3. Disable conflicting modules in Responder.conf (e.g., set SMB = Off)"
	echo ""
	echo "Continuing with limited functionality in 5 seconds..."
	echo "==========================================================================="
	sleep 5
	SIP_ENABLED=true
else
	echo "  System Integrity Protection is disabled. Full service management available."
	SIP_ENABLED=false
fi

# Helper: get process name from lsof output (handles whitespace padding)
get_proc_name() {
	awk 'NR>1 && !/launchd/ {print $1; exit}'
}

# Stop known conflicting daemons
if [[ "$SIP_ENABLED" = false ]]; then
	echo "Stopping potentially conflicting macOS services..."
	for DAEMON in "${KNOWN_DAEMONS[@]}"; do
		PLIST="/System/Library/LaunchDaemons/${DAEMON}.plist"
		if [[ -e "$PLIST" ]]; then
			if launchctl bootout system "$PLIST" 2>/dev/null; then
				echo "  Stopped $DAEMON"
				SVC_LIST+=("$DAEMON")
			fi
		fi
	done

	# Scan for any other processes holding Responder's ports
	echo "Checking for port conflicts..."
	for PORT in "${TCP_LIST[@]}"; do
		PROC=$(lsof +c 0 -iTCP:"$PORT" -sTCP:LISTEN -nP 2>/dev/null | get_proc_name)
		if [[ -n "$PROC" ]]; then
			echo "  Found $PROC listening on TCP port $PORT"
			AGENT=$(launchctl list 2>/dev/null | grep -Fm 1 "$PROC" | awk '{print $NF}' | sed 's/\.reloaded$//')
			if [[ -n "$AGENT" ]]; then
				PLIST="/System/Library/LaunchDaemons/${AGENT}.plist"
				if [[ -e "$PLIST" ]] && launchctl bootout system "$PLIST" 2>/dev/null; then
					SVC_LIST+=("$AGENT")
					echo "  Stopped $AGENT"
				else
					echo "  Could not stop $AGENT (may need manual intervention)"
				fi
			fi
		fi
	done

	for PORT in "${UDP_LIST[@]}"; do
		PROC=$(lsof +c 0 -iUDP:"$PORT" -nP 2>/dev/null | grep -Ev '(127\.|::1)' | get_proc_name)
		if [[ -n "$PROC" ]]; then
			echo "  Found $PROC listening on UDP port $PORT"
			AGENT=$(launchctl list 2>/dev/null | grep -Fm 1 "$PROC" | awk '{print $NF}' | sed 's/\.reloaded$//')
			if [[ -n "$AGENT" ]]; then
				PLIST="/System/Library/LaunchDaemons/${AGENT}.plist"
				if [[ -e "$PLIST" ]] && launchctl bootout system "$PLIST" 2>/dev/null; then
					SVC_LIST+=("$AGENT")
					echo "  Stopped $AGENT"
				else
					echo "  Could not stop $AGENT (may need manual intervention)"
				fi
			fi
		fi
	done
else
	echo "Checking for port conflicts (informational only - cannot stop services with SIP enabled)..."
	CONFLICTS_FOUND=false
	for PORT in "${TCP_LIST[@]}"; do
		PROC=$(lsof +c 0 -iTCP:"$PORT" -sTCP:LISTEN -nP 2>/dev/null | get_proc_name)
		if [[ -n "$PROC" ]]; then
			echo "  WARNING: $PROC is using TCP port $PORT"
			CONFLICTS_FOUND=true
		fi
	done
	for PORT in "${UDP_LIST[@]}"; do
		PROC=$(lsof +c 0 -iUDP:"$PORT" -nP 2>/dev/null | grep -Ev '(127\.|::1)' | get_proc_name)
		if [[ -n "$PROC" ]]; then
			echo "  WARNING: $PROC is using UDP port $PORT"
			CONFLICTS_FOUND=true
		fi
	done

	if [[ "$CONFLICTS_FOUND" = true ]]; then
		echo ""
		echo "Port conflicts detected! Consider:"
		echo "  1. Disabling SIP to allow automatic service management"
		echo "  2. Editing Responder.conf to disable conflicting modules"
		echo "  3. Manually stopping the conflicting services"
		echo ""
	fi
fi

# Launch Responder
echo ""
echo "Launching Responder..."
echo "==========================================================================="
/usr/bin/env python3 "$SCRIPT_DIR/Responder.py" "$@"
