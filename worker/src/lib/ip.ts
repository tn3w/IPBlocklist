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
