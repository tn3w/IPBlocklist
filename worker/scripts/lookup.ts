import { readFileSync } from "node:fs"
import { performance } from "node:perf_hooks"
import { IntelDb } from "../src/lib/intel"

const args = process.argv.slice(2)
const path = args[0]?.endsWith(".bin") ? args.shift()! : "intel.bin"

const bytes = readFileSync(path)
const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)

const loadStart = performance.now()
const db = new IntelDb(buffer)
const loadMs = performance.now() - loadStart

for (const ip of args) {
	const start = performance.now()
	const result = db.lookup(ip)
	const lookupMs = performance.now() - start
	console.log(JSON.stringify({ ...result, _perf: { loadMs, lookupMs } }, null, 2))
}
