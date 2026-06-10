export const isV6 = (ip: string) => ip.includes(":")

function v4ToInt(text: string): bigint {
	let value = 0n
	for (const part of text.split(".")) value = (value << 8n) | BigInt(part)
	return value
}

function v6ToInt(text: string): bigint {
	const [head, tail] = text.split("::")
	const heads = head ? head.split(":") : []
	const tails = tail !== undefined && tail ? tail.split(":") : []
	const missing = tail === undefined ? 0 : 8 - heads.length - tails.length
	const groups = [...heads, ...Array(missing).fill("0"), ...tails]
	let value = 0n
	for (const group of groups) value = (value << 16n) | BigInt(parseInt(group || "0", 16))
	return value
}

export const ipToInt = (ip: string) => (isV6(ip) ? v6ToInt(ip) : v4ToInt(ip))

function isValidV4(ip: string): boolean {
	const parts = ip.split(".")
	if (parts.length !== 4) return false
	return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

function isValidV6(ip: string): boolean {
	const halves = ip.split("::")
	if (halves.length > 2) return false
	const hasGap = halves.length === 2
	const head = halves[0] ? halves[0].split(":") : []
	const tail = hasGap && halves[1] ? halves[1].split(":") : []
	const groups = [...head, ...tail]
	if (!hasGap && groups.length !== 8) return false
	if (hasGap && groups.length > 7) return false
	return groups.every((group) => /^[0-9a-fA-F]{1,4}$/.test(group))
}

export const isValidIp = (ip: string) => (isV6(ip) ? isValidV6(ip) : isValidV4(ip))

const RESERVED: Record<string, [string, number, string][]> = {
	v4: [
		["0.0.0.0", 8, "unspecified"],
		["10.0.0.0", 8, "private"],
		["100.64.0.0", 10, "shared"],
		["127.0.0.0", 8, "loopback"],
		["169.254.0.0", 16, "link_local"],
		["172.16.0.0", 12, "private"],
		["192.0.0.0", 24, "reserved"],
		["192.0.2.0", 24, "documentation"],
		["192.168.0.0", 16, "private"],
		["198.18.0.0", 15, "benchmark"],
		["198.51.100.0", 24, "documentation"],
		["203.0.113.0", 24, "documentation"],
		["224.0.0.0", 4, "multicast"],
		["240.0.0.0", 4, "reserved"],
	],
	v6: [
		["::", 128, "unspecified"],
		["::1", 128, "loopback"],
		["64:ff9b::", 96, "reserved"],
		["100::", 64, "discard"],
		["2001:db8::", 32, "documentation"],
		["fc00::", 7, "private"],
		["fe80::", 10, "link_local"],
		["ff00::", 8, "multicast"],
	],
}

const ranges = (key: "v4" | "v6", bits: number) =>
	RESERVED[key].map(([base, prefix, scope]) => {
		const shift = BigInt(bits - prefix)
		return { net: ipToInt(base) >> shift, shift, scope }
	})
const RESERVED_RANGES = { v4: ranges("v4", 32), v6: ranges("v6", 128) }

export function ipScope(ip: string): string {
	const value = ipToInt(ip)
	const found = RESERVED_RANGES[isV6(ip) ? "v6" : "v4"].find(
		(range) => value >> range.shift === range.net,
	)
	return found ? found.scope : ""
}
