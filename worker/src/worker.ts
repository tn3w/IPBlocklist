import bin from "../../intel.bin"
import { IntelDb } from "./lib/intel"

const db = new IntelDb(bin as ArrayBuffer)
db.lookup("8.8.8.8") // warm v4 path
db.lookup("2606:4700:4700::1111") // warm v6 path

export default {
	async fetch(request: Request, _env: unknown, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url)
		const queryIp = url.searchParams.get("ip")
		const ip = queryIp || request.headers.get("CF-Connecting-IP") || ""
		if (!ip) return json({ error: "no ip" }, 400, "no-store")

		if (!queryIp) return json(db.lookup(ip), 200, "private, max-age=3600")

		const cached = await caches.default.match(request)
		if (cached) return cached

		const response = json(db.lookup(ip), 200, "public, max-age=3600")
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
