#!/bin/sh
set -eu

base_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
blacklist_dir="$base_dir/datasets/blacklist"
whitelist_dir="$base_dir/datasets/whitelist"

mkdir -p "$blacklist_dir" "$whitelist_dir"

fetch()
{
	url=$1
	out=$2
	tmp="${out}.tmp"
	raw="${out}.raw"

	printf 'fetching %s\n' "$url" >&2
	curl -fsSL "$url" > "$raw"
	awk '
		{
			sub(/\r$/, "")
			gsub(/;.*/, "")
			gsub(/#.*/, "")
			for (i = 1; i <= NF; i++) {
				if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/)
					print $i
			}
		}
	' < "$raw" |
		sort -u > "$tmp"
	rm -f "$raw"

	mv "$tmp" "$out"
}

fetch "https://iplists.firehol.org/files/firehol_level1.netset" \
	"$blacklist_dir/firehol.txt"
fetch "https://www.spamhaus.org/drop/drop.txt" \
	"$blacklist_dir/spamhaus-drop.txt"
fetch "https://www.spamhaus.org/drop/edrop.txt" \
	"$blacklist_dir/spamhaus-edrop.txt"
fetch "https://check.torproject.org/torbulkexitlist" \
	"$blacklist_dir/tor.txt"
fetch "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" \
	"$blacklist_dir/malware.txt"

if [ ! -f "$whitelist_dir/trusted.txt" ]; then
	cat > "$whitelist_dir/trusted.txt" <<'EOF'
# Add local trusted IPv4 addresses or CIDRs here, one per line.
# Example:
# 192.168.1.0/24
EOF
fi

printf 'datasets updated under %s\n' "$base_dir/datasets" >&2
