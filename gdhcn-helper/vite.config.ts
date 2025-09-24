// vite.config.ts
import { defineConfig, Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import YAML from 'yaml'

// ---------- helpers (paste these under the imports) ----------

const DEFAULT_HOST = process.env.MOCK_HOST || 'fhir-mock.test'
const DEFAULT_PORT = process.env.MOCK_PORT || '8182'
const DEFAULT_SCHEME = process.env.MOCK_SCHEME || 'http'
function baseUrl() {
  return process.env.PUBLIC_BASE || `${DEFAULT_SCHEME}://${DEFAULT_HOST}:${DEFAULT_PORT}`
}

type OneOrMany<T> = T | T[]
type BundleRule = { pin: string; key: OneOrMany<string>; file?: string }
type Config = { bundles: Record<string, BundleRule> }

const GENERIC_MSG = 'Not available'
const GENERIC_STATUS = 404 // same code for any failure (avoid info leaks)

// generic, non-leaky failure responses
function denyManifest(res: any) {
  res.statusCode = GENERIC_STATUS
  res.setHeader('Content-Type', 'application/json')
  res.end(JSON.stringify({ error: 'not_available', message: GENERIC_MSG }))
}
function denyFhir(res: any) {
  res.statusCode = GENERIC_STATUS
  res.setHeader('Content-Type', 'application/json')
  res.end(JSON.stringify({ found: false, fhir: [], errors: [GENERIC_MSG] }))
}

// safe equality to reduce timing hints
function timingSafeEqualStr(a: string, b: string) {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  const max = Math.max(ab.length, bb.length)
  const pab = Buffer.concat([ab, Buffer.alloc(max - ab.length)])
  const pbb = Buffer.concat([bb, Buffer.alloc(max - bb.length)])
  return crypto.timingSafeEqual(pab, pbb) && a.length === b.length
}

// config + path utils
function loadConfig(): Config {
  const p = path.join(process.cwd(), 'config', 'manifest.yaml')
  if (!fs.existsSync(p)) return { bundles: {} }
  const txt = fs.readFileSync(p, 'utf8')
  return (YAML.parse(txt) as Config) || { bundles: {} }
}
function bundlePathFor(id: string, rule?: BundleRule) {
  const file = rule?.file || `${id}.json`
  return path.join(process.cwd(), 'public', 'bundles', file)
}
function hasKey(rule: BundleRule, incoming: string | null) {
  if (!incoming) return false
  const k = rule.key
  return Array.isArray(k) ? k.includes(incoming) : timingSafeEqualStr(k, incoming)
}
function keyForLocation(rule: BundleRule) {
  return Array.isArray(rule.key) ? rule.key[0] : rule.key
}

// request body / pin helpers
function readJsonBody(req: any, timeoutMs = 3000): Promise<any> {
  return new Promise(resolve => {
    const chunks: Buffer[] = []
    let done = false
    const finish = (obj: any) => { if (!done) { done = true; resolve(obj) } }
    const t = setTimeout(() => finish({}), timeoutMs)
    req.on('data', (c: Buffer) => chunks.push(c))
    req.on('end', () => {
      clearTimeout(t)
      try { finish(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')) }
      catch { finish({}) }
    })
    req.on('error', () => { clearTimeout(t); finish({}) })
  })
}
function getPinFromReq(req: any, queryStr?: string) {
  const q = new URLSearchParams(queryStr || '')
  const headerPin =
    (req.headers['x-pin'] as string | undefined) ??
    (req.headers['x-passcode'] as string | undefined)
  const queryPin = q.get('pin') ?? q.get('passcode')
  return { headerPin, queryPin }
}

// ---------- mock API plugin ----------

function mockApi(): Plugin {
  return {
    name: 'mock-fhir-api',
    configureServer(server) {
      const app = server.middlewares

      // AUTHORIZE/MANIFEST: GET or POST /v2/manifests/:id  (generic failure on any problem)
      app.use(async (req, res, next) => {
        const m = req.url?.match(/^\/v2\/manifests\/([a-zA-Z0-9-]+)(?:\?(.*))?$/)
        if (!m) return next()

        const id = m[1]
        const { headerPin, queryPin } = getPinFromReq(req, m[2])
        const cfg = loadConfig()
        const rule = cfg.bundles?.[id]

        if (!rule) return denyManifest(res)

        let bodyPin: string | undefined
        if (req.method === 'POST') {
          const body = await readJsonBody(req)
          bodyPin = body?.pin ?? body?.passcode
        }

        const providedPin = String(bodyPin ?? queryPin ?? headerPin ?? '')
        if (!timingSafeEqualStr(providedPin, String(rule.pin))) {
          return denyManifest(res)
        }

        const key = keyForLocation(rule)
            const location = `${baseUrl()}/v2/ips-json/${id}?key=${encodeURIComponent(key)}`
            res.setHeader('Content-Type', 'application/json')
            res.end(JSON.stringify({
            manifest: { files: [{ contentType: 'application/fhir+json', location }] }
        }))
    })


    // inside configureServer(server)
      app.use((req, res, next) => {
          if (req.method === 'GET' && req.url === '/__ping') {
          res.setHeader('Content-Type', 'text/plain')
          return res.end('ok')
          }
          next()
      })

      // FETCH: GET /v2/ips-json/:id?key=...  (generic failure on any problem)
      app.use((req, res, next) => {
        const m = req.url?.match(/^\/v2\/ips-json\/([a-zA-Z0-9-]+)(?:\?(.*))?$/)
        if (!m) return next()

        const id = m[1]
        const q = new URLSearchParams(m[2] || '')
        const incomingKey = q.get('key')

        const cfg = loadConfig()
        const rule = cfg.bundles?.[id]
        if (!rule) return denyFhir(res)
        if (!hasKey(rule, incomingKey)) return denyFhir(res)

        const filePath = bundlePathFor(id, rule)
        if (!fs.existsSync(filePath)) return denyFhir(res)

        try {
          const bundle = JSON.parse(fs.readFileSync(filePath, 'utf8'))
          const returnedUrl = `${baseUrl()}/v2/ips-json/${id}?key=${encodeURIComponent(incomingKey!)}`
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify({
            found: true,
            fhir: [{ url: returnedUrl, resource: bundle }],
            errors: []
          }))
        } catch {
          return denyFhir(res)
        }
      })
    }
  }
}

// ---------- export vite config ----------
export default defineConfig({
  plugins: [react(), mockApi()],
  server: { port: 5173 }
})
