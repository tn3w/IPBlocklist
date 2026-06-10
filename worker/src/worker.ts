import { IntelDb } from "./lib/intel"
import { isValidIp } from "./lib/ip"

type Env = { INTEL: KVNamespace; INTEL_KEY?: string }

let db: IntelDb | null = null
let loading: Promise<IntelDb> | null = null

async function getDb(env: Env): Promise<IntelDb> {
	if (db) return db
	if (!loading) loading = load(env)
	return loading
}

async function load(env: Env): Promise<IntelDb> {
	const buffer = await env.INTEL.get(env.INTEL_KEY || "intel.bin", "arrayBuffer")
	if (!buffer) throw new Error("intel.bin missing from KV")
	const loaded = new IntelDb(buffer)
	loaded.lookup("8.8.8.8") // warm v4 path
	loaded.lookup("2606:4700:4700::1111") // warm v6 path
	db = loaded
	return loaded
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url)
		const queryIp = url.searchParams.get("ip")
		const ip = (queryIp || request.headers.get("CF-Connecting-IP") || "").trim()
		if (!ip) return json({ error: "no ip" }, 400, "no-store")
		if (!isValidIp(ip)) return json({ error: "invalid ip", ip }, 400, "no-store")

		const intel = await getDb(env)
		if (!queryIp) return json(intel.lookup(ip), 200, "private, max-age=3600")

		const cached = await caches.default.match(request)
		if (cached) return cached

		const response = json(intel.lookup(ip), 200, "public, max-age=3600")
		ctx.waitUntil(caches.default.put(request, response.clone()))
		return response
	},
}

function json(body: unknown, status = 200, cacheControl = "no-store"): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json", "cache-control": cacheControl },
	})
}
