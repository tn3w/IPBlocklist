import { isV6, ipToInt, ipScope } from "./ip"

export const FLAGS = [
	"vpn",
	"proxy",
	"tor",
	"malware",
	"c2",
	"scanner",
	"brute_force",
	"spammer",
	"compromised",
	"datacenter",
	"cdn",
	"anycast",
	"crawler",
	"bot",
	"cloud",
	"private_relay",
	"anonymizer",
	"mobile",
	"isp",
	"government",
] as const

const SEVERITY = [
	30, 25, 45, 95, 95, 55, 70, 65, 75, 15, 5, 0, 10, 40, 10, 15, 35, 0, 0, 0,
]
const LEVELS: [number, string][] = [
	[80, "critical"],
	[60, "high"],
	[35, "medium"],
	[15, "low"],
]

const BGPTOOLS_THREAT = new Set([
	"vpn",
	"proxy",
	"tor",
	"anonymizer",
	"malware",
	"c2",
	"scanner",
	"brute_force",
	"spammer",
	"compromised",
	"bot",
])

const bgptoolsPenalty = (source: string, flag: string) =>
	!source.startsWith("bgptools") ? 1 : BGPTOOLS_THREAT.has(flag) ? 0.35 : 0.6

const V4_BUCKETS = 65536

export type Match = {
	source: string
	provider: string
	range: string
	flags: string[]
	weight: number
}
export type Result = {
	ip: string
	found: boolean
	verdict: string
	score: number
	detections: number
	sources: number
	top_provider: string
	providers: string[]
	flags: string[]
	reasons: string[]
	matches: Match[]
}

const round1 = (value: number) => Math.round(value * 10) / 10

export class IntelDb {
	private view: DataView
	private bytes: Uint8Array
	private bucket: Uint32Array
	private startsLo: Uint16Array
	private lens: Uint16Array
	private vals: Uint16Array
	private maxEndsLo: Uint16Array
	private lstarts: Uint32Array
	private lends: Uint32Array
	private lvals: Uint16Array
	private lmax: Uint32Array
	private v6starts: bigint[]
	private v6ends: bigint[]
	private v6vals: Uint16Array
	private v6max: bigint[]
	private valueTable: Uint32Array
	private strings: string[]
	private weights: number[]

	constructor(buffer: ArrayBuffer) {
		this.bytes = new Uint8Array(buffer)
		this.view = new DataView(buffer)
		if (this.view.getUint32(0, true) !== 6) throw new Error("unsupported intel.bin version")

		const head = (index: number) => Number(this.view.getBigUint64(8 + index * 8, true))
		const cn = head(0)
		const ln = head(1)
		const v6n = head(2)
		const valn = head(3)
		const strn = head(4)
		const off = Array.from({ length: 14 }, (_, i) => head(5 + i))

		this.bucket = this.u32(off[0], V4_BUCKETS + 1)
		this.startsLo = this.u16(off[1], cn)
		this.lens = this.u16(off[2], cn)
		this.vals = this.u16(off[3], cn)
		this.lstarts = this.u32(off[4], ln)
		this.lends = this.u32(off[5], ln)
		this.lvals = this.u16(off[6], ln)
		this.valueTable = this.u32(off[10], valn * 4)

		this.strings = this.readStrings(strn, off[11], off[12])
		this.maxEndsLo = this.buildMaxEndsLo()
		this.lmax = this.prefixMax32(this.lends)
		;[this.v6starts, this.v6ends] = this.readV6(v6n, off[7], off[8])
		this.v6vals = this.u16(off[9], v6n)
		this.v6max = this.prefixMaxBig(this.v6ends)
		this.weights = this.buildWeights()
	}

	private u16(offset: number, count: number): Uint16Array {
		if (!count) return new Uint16Array(0)
		const base = this.bytes.byteOffset + offset
		if (base % 2 === 0) return new Uint16Array(this.bytes.buffer, base, count)
		const out = new Uint16Array(count)
		for (let i = 0; i < count; i++) out[i] = this.view.getUint16(offset + i * 2, true)
		return out
	}

	private u32(offset: number, count: number): Uint32Array {
		if (!count) return new Uint32Array(0)
		const base = this.bytes.byteOffset + offset
		if (base % 4 === 0) return new Uint32Array(this.bytes.buffer, base, count)
		const out = new Uint32Array(count)
		for (let i = 0; i < count; i++) out[i] = this.view.getUint32(offset + i * 4, true)
		return out
	}

	private readStrings(count: number, indexOff: number, dataOff: number): string[] {
		const decoder = new TextDecoder()
		const out: string[] = []
		for (let i = 0; i < count; i++) {
			const offset = this.view.getUint32(indexOff + i * 8, true)
			const length = this.view.getUint32(indexOff + i * 8 + 4, true)
			out.push(
				decoder.decode(this.bytes.subarray(dataOff + offset, dataOff + offset + length)),
			)
		}
		return out
	}

	private readV6(count: number, startsOff: number, endsOff: number): [bigint[], bigint[]] {
		const starts: bigint[] = []
		const ends: bigint[] = []
		for (let i = 0; i < count; i++) {
			const sLo = this.view.getBigUint64(startsOff + i * 16, true)
			const sHi = this.view.getBigUint64(startsOff + i * 16 + 8, true)
			starts.push((sHi << 64n) | sLo)
			const eLo = this.view.getBigUint64(endsOff + i * 16, true)
			const eHi = this.view.getBigUint64(endsOff + i * 16 + 8, true)
			ends.push((eHi << 64n) | eLo)
		}
		return [starts, ends]
	}

	private buildMaxEndsLo(): Uint16Array {
		const out = new Uint16Array(this.startsLo.length)
		for (let b = 0; b < V4_BUCKETS; b++) {
			const start = this.bucket[b]
			const end = this.bucket[b + 1]
			let running = 0
			for (let i = start; i < end; i++) {
				const endLo = (this.startsLo[i] + this.lens[i]) & 0xffff
				if (endLo > running) running = endLo
				out[i] = running
			}
		}
		return out
	}

	private prefixMax32(values: Uint32Array): Uint32Array {
		const out = new Uint32Array(values.length)
		let running = 0
		for (let i = 0; i < values.length; i++) {
			if (values[i] > running) running = values[i]
			out[i] = running
		}
		return out
	}

	private prefixMaxBig(values: bigint[]): bigint[] {
		const out: bigint[] = []
		let running = 0n
		for (const value of values) {
			if (value > running) running = value
			out.push(running)
		}
		return out
	}

	private buildWeights(): number[] {
		const total = this.vals.length + this.lvals.length
		if (!total) return [...SEVERITY]
		const counts = new Array(20).fill(0)
		const tally = (vals: Uint16Array) => {
			for (const value of vals) {
				const bits = this.valueTable[value * 4]
				for (let i = 0; i < 20; i++) if (bits & (1 << i)) counts[i]++
			}
		}
		tally(this.vals)
		tally(this.lvals)
		return SEVERITY.map((severity, i) => {
			const prevalence = Math.max(counts[i] / total, 1 / total)
			return severity * (1 + Math.log2(1 / prevalence) / 24)
		})
	}

	private render(start: bigint, end: bigint, valueId: number, v6: boolean): Match {
		const bits = this.valueTable[valueId * 4]
		const source = this.strings[this.valueTable[valueId * 4 + 2]]
		const flags: string[] = []
		let weight = 0
		for (let i = 0; i < 20; i++) {
			if (!(bits & (1 << i))) continue
			flags.push(FLAGS[i])
			const w = this.weights[i] * bgptoolsPenalty(source, FLAGS[i])
			if (w > weight) weight = w
		}
		const fmt = v6 ? formatV6 : formatV4
		return {
			source,
			provider: this.strings[this.valueTable[valueId * 4 + 1]],
			range: `${fmt(start)}-${fmt(end)}`,
			flags,
			weight: round1(weight),
		}
	}

	private lookupV4(ip: number): Match[] {
		const out: Match[] = []
		const bucket = ip >>> 16
		const ipLo = ip & 0xffff
		const start = this.bucket[bucket]
		const end = this.bucket[bucket + 1]
		if (start < end) {
			let i = upperBound16(this.startsLo, start, end, ipLo)
			const prefix = (bucket << 16) >>> 0
			while (i > start) {
				i--
				if (this.maxEndsLo[i] < ipLo) break
				const endLo = (this.startsLo[i] + this.lens[i]) & 0xffff
				if (endLo >= ipLo)
					out.push(
						this.render(
							BigInt((prefix | this.startsLo[i]) >>> 0),
							BigInt((prefix | endLo) >>> 0),
							this.vals[i],
							false,
						),
					)
			}
		}
		if (this.lstarts.length) {
			let i = upperBound32(this.lstarts, ip)
			while (i > 0) {
				i--
				if (this.lmax[i] < ip) break
				if (this.lends[i] >= ip)
					out.push(
						this.render(
							BigInt(this.lstarts[i] >>> 0),
							BigInt(this.lends[i] >>> 0),
							this.lvals[i],
							false,
						),
					)
			}
		}
		return out
	}

	private lookupV6(ip: bigint): Match[] {
		const out: Match[] = []
		if (!this.v6starts.length) return out
		let i = upperBoundBig(this.v6starts, ip)
		while (i > 0) {
			i--
			if (this.v6max[i] < ip) break
			if (this.v6ends[i] >= ip)
				out.push(this.render(this.v6starts[i], this.v6ends[i], this.v6vals[i], true))
		}
		return out
	}

	lookup(ip: string): Result {
		const scope = ipScope(ip)
		if (scope) return reservedResult(ip, scope)
		const v6 = isV6(ip)
		const value = ipToInt(ip)
		const matches = v6 ? this.lookupV6(value) : this.lookupV4(Number(value))
		matches.sort((a, b) => b.weight - a.weight)
		return this.summarize(ip, matches)
	}

	private summarize(ip: string, matches: Match[]): Result {
		const flagWeight = new Map<string, number>()
		for (const match of matches)
			for (const flag of match.flags) {
				const base = this.weights[FLAGS.indexOf(flag as (typeof FLAGS)[number])]
				const weight = base * bgptoolsPenalty(match.source, flag)
				if (weight > (flagWeight.get(flag) ?? 0)) flagWeight.set(flag, weight)
			}
		const ranked = [...flagWeight.entries()].sort((a, b) => b[1] - a[1])
		const sources = new Set(matches.map((m) => `${m.provider}|${m.source}`))

		let score = 0
		if (ranked.length) {
			const top = ranked[0][1]
			const extras = ranked.slice(1).reduce((sum, [, w]) => sum + w, 0) * 0.15
			const boost = 1 + 0.08 * Math.log2(sources.size + 1)
			score = round1(Math.min(100, (top + extras) * boost))
		}

		const allFlags: string[] = []
		for (const match of matches)
			for (const flag of match.flags) if (!allFlags.includes(flag)) allFlags.push(flag)

		const providers: string[] = []
		for (const match of matches)
			if (match.provider && !providers.includes(match.provider))
				providers.push(match.provider)
		const torIndex = providers.findIndex((p) => p.toLowerCase() === "tor")
		if (torIndex >= 0) (providers.splice(torIndex, 1), providers.unshift("Tor"))

		return {
			ip,
			found: matches.length > 0,
			verdict: matches.length ? levelFor(score) : "clean",
			score,
			detections: matches.length,
			sources: sources.size,
			top_provider: providers[0] ?? "",
			providers,
			flags: allFlags,
			reasons: ranked.slice(0, 5).map(([flag]) => flag),
			matches,
		}
	}
}

function reservedResult(ip: string, scope: string): Result {
	return {
		ip,
		found: false,
		verdict: scope,
		score: 0,
		detections: 0,
		sources: 0,
		top_provider: "",
		providers: [],
		flags: [],
		reasons: [scope],
		matches: [],
	}
}

function levelFor(score: number): string {
	for (const [threshold, name] of LEVELS) if (score >= threshold) return name
	return "minimal"
}

function upperBound16(
	array: Uint16Array,
	lo: number,
	hi: number,
	target: number,
): number {
	while (lo < hi) {
		const mid = (lo + hi) >>> 1
		if (array[mid] > target) hi = mid
		else lo = mid + 1
	}
	return lo
}

function upperBound32(array: Uint32Array, target: number): number {
	let lo = 0,
		hi = array.length
	while (lo < hi) {
		const mid = (lo + hi) >>> 1
		if (array[mid] > target) hi = mid
		else lo = mid + 1
	}
	return lo
}

function upperBoundBig(array: bigint[], target: bigint): number {
	let lo = 0,
		hi = array.length
	while (lo < hi) {
		const mid = (lo + hi) >>> 1
		if (array[mid] > target) hi = mid
		else lo = mid + 1
	}
	return lo
}

function formatV4(value: bigint): string {
	const n = Number(value)
	return `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`
}

function formatV6(value: bigint): string {
	const groups: string[] = []
	for (let shift = 112n; shift >= 0n; shift -= 16n)
		groups.push(Number((value >> shift) & 0xffffn).toString(16))
	let best = -1,
		bestLength = 0,
		run = -1,
		length = 0
	for (let i = 0; i < 8; i++) {
		if (groups[i] === "0") {
			if (run < 0) run = i
			length++
			if (length > bestLength) {
				best = run
				bestLength = length
			}
		} else {
			run = -1
			length = 0
		}
	}
	if (bestLength < 2) return groups.join(":")
	return `${groups.slice(0, best).join(":")}::${groups.slice(best + bestLength).join(":")}`
}
