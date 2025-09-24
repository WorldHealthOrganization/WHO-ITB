import React, { useState } from 'react'

export default function App() {
  const [pin, setPin] = useState('1234')
  const [id, setId] = useState('ba07611d-b9c8-4104-a086-554d8b6cc014')
  const [manifest, setManifest] = useState<any>(null)
  const [fhir, setFhir] = useState<any>(null)

  async function authorize() {
    setFhir(null)
    setManifest(null)
    const res = await fetch(`/v2/manifests/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ passcode: pin, pin })
    })
    const json = await res.json()
    setManifest(json)
  }

  async function fetchFhir() {
    if (!manifest?.manifest?.files?.length) return
    const file = manifest.manifest.files[0]
    const res = await fetch(file.location, { method: 'GET' })
    const json = await res.json()
    setFhir(json)
  }

  return (
    <div style={{ fontFamily: 'system-ui, sans-serif', padding: 16, maxWidth: 900, margin: '0 auto' }}>
      <h1>FHIR Mock Server</h1>

      <section style={{ marginBottom: 24, padding: 12, border: '1px solid #ddd', borderRadius: 8 }}>
        <h2>5. Authorize with PIN</h2>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <label>ID: <input value={id} onChange={e => setId(e.target.value)} style={{ width: 420 }} /></label>
          <label>PIN: <input value={pin} onChange={e => setPin(e.target.value)} style={{ width: 120 }} /></label>
          <button onClick={authorize}>Authorize</button>
        </div>
        <pre style={{ background: '#f6f8fa', padding: 12, overflow: 'auto', marginTop: 12 }}>
{JSON.stringify(manifest ?? {}, null, 2)}
        </pre>
      </section>

      <section style={{ marginBottom: 24, padding: 12, border: '1px solid #ddd', borderRadius: 8 }}>
        <h2>6. Fetch FHIR Resources</h2>
        <button onClick={fetchFhir} disabled={!manifest}>Fetch FHIR</button>
        <pre style={{ background: '#f6f8fa', padding: 12, overflow: 'auto', marginTop: 12 }}>
{JSON.stringify(fhir ?? {}, null, 2)}
        </pre>
      </section>
    </div>
  )
}
