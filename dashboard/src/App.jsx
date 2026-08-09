import { useCallback, useEffect, useMemo, useState } from 'react'
import './App.css'

const defaultEndpoint = import.meta.env.VITE_PV_API_URL ?? ''

function StatusPill({ state }) {
  return <span className={`status status--${state}`}>{state}</span>
}

function Metric({ label, value, hint }) {
  return (
    <article className="metric">
      <p>{label}</p>
      <strong>{value}</strong>
      <span>{hint}</span>
    </article>
  )
}

function App() {
  const [endpoint, setEndpoint] = useState(defaultEndpoint)
  const [apiKey, setApiKey] = useState(import.meta.env.VITE_PV_DEMO_API_KEY ?? '')
  const [snapshot, setSnapshot] = useState(null)
  const [state, setState] = useState('checking')
  const [error, setError] = useState('')

  const request = useCallback(
    async (path, optional = false) => {
      const response = await fetch(`${endpoint.replace(/\/$/, '')}${path}`, {
        headers: apiKey ? { 'X-API-Key': apiKey } : {},
      })
      if (!response.ok) {
        if (optional && [401, 403].includes(response.status)) return null
        throw new Error(`${path} returned HTTP ${response.status}`)
      }
      return response.json()
    },
    [apiKey, endpoint],
  )

  const refresh = useCallback(async () => {
    setState('checking')
    setError('')
    try {
      const [health, ready] = await Promise.all([
        request('/health'),
        request('/ready', true),
      ])
      const [runtime, blocked, divergent, verification, ops] = await Promise.all([
        request('/v1/runtime', true),
        request('/v1/blocked', true),
        request('/v1/divergent', true),
        request('/v1/verify', true),
        request('/v1/ops/summary', true),
      ])
      setSnapshot({ health, ready, runtime, blocked, divergent, verification, ops })
      setState(ready?.status === 'ready' ? 'ready' : 'healthy')
    } catch (cause) {
      setSnapshot(null)
      setState('offline')
      setError(cause instanceof Error ? cause.message : 'Connection failed')
    }
  }, [request])

  useEffect(() => {
    refresh()
  }, [refresh])

  const composition = useMemo(
    () => Object.entries(snapshot?.runtime?.composition ?? {}),
    [snapshot],
  )
  const attached = composition.filter(([, item]) => item.status === 'attached').length
  const blocked = snapshot?.blocked?.length ?? snapshot?.blocked?.records?.length ?? '—'
  const divergent =
    snapshot?.divergent?.length ?? snapshot?.divergent?.records?.length ?? '—'
  const chainState = snapshot?.verification
    ? snapshot.verification.valid === false
      ? 'attention'
      : 'verified'
    : 'locked'

  return (
    <main>
      <header className="topbar">
        <a className="brand" href="#overview" aria-label="PrivateVault home">
          <span className="brand__mark">PV</span>
          <span>
            <b>PrivateVault</b>
            <small>Agent Security Console</small>
          </span>
        </a>
        <div className="topbar__status">
          <StatusPill state={state} />
          <button type="button" onClick={refresh}>Refresh</button>
        </div>
      </header>

      <section className="hero" id="overview">
        <div>
          <p className="eyebrow">Decision security platform · v0.4.0</p>
          <h1>Control the action.<br />Prove the decision.</h1>
          <p className="lede">
            Multi-agent dual-control on every decide with a shared execution id,
            loop discovery at authorize, readiness and Prometheus metrics, and
            independently verifiable audit export. Single-tenant self-hosted.
          </p>
        </div>
        <div className="connection" aria-label="Runtime connection">
          <label>
            Runtime URL
            <input
              value={endpoint}
              onChange={(event) => setEndpoint(event.target.value)}
              placeholder="Same origin"
            />
          </label>
          <label>
            API key <span>kept in memory only</span>
            <input
              type="password"
              value={apiKey}
              onChange={(event) => setApiKey(event.target.value)}
              placeholder="Required for operator data"
              autoComplete="off"
            />
          </label>
          {error && <p className="connection__error">{error}</p>}
        </div>
      </section>

      <section className="metrics" aria-label="Runtime summary">
        <Metric label="Runtime" value={state} hint={snapshot?.ready?.auth_enabled ? 'Auth on' : 'Readiness boundary'} />
        <Metric label="Controls attached" value={composition.length ? `${attached}/${composition.length}` : '—'} hint="Live composition" />
        <Metric
          label="Decisions"
          value={snapshot?.ops?.metrics?.total_decisions ?? '—'}
          hint="Ops summary"
        />
        <Metric label="Blocked actions" value={blocked} hint="Credential scope" />
        <Metric label="Divergence" value={divergent} hint="Blocked but executed" />
        <Metric label="Audit chain" value={chainState} hint="Independent evidence" />
      </section>

      <section className="panel-grid">
        <article className="panel panel--wide">
          <div className="panel__heading">
            <div>
              <p className="eyebrow">Enforcement plane</p>
              <h2>Runtime composition</h2>
            </div>
            <span>{apiKey ? 'operator scope requested' : 'add a key to inspect'}</span>
          </div>
          {composition.length ? (
            <div className="control-list">
              {composition.map(([name, item]) => (
                <div className="control" key={name}>
                  <span className={`control__dot control__dot--${item.status}`} />
                  <b>{name.replaceAll('_', ' ')}</b>
                  <span className="control__state">{item.status}</span>
                  <p>{item.detail}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty">
              Runtime health is public; composition requires a full-scope API key.
            </div>
          )}
        </article>

        <article className="panel panel--loop">
          <p className="eyebrow">Offline experimentation</p>
          <h2>Discovery Loop</h2>
          <p>
            Sealed decisions become replayed, evidence-linked policy proposals.
            The enforcement plane stays unchanged.
          </p>
          <ol>
            <li><span>01</span>Mine sealed evidence <b>PROPOSE</b></li>
            <li><span>02</span>Replay history + attacks <b>RUN</b></li>
            <li><span>03</span>Gate + structural probes <b>EVALUATE</b></li>
            <li><span>04</span>Human-reviewed policy PR <b>ITERATE</b></li>
          </ol>
          <code>pv discover run --history-db decisions.db</code>
        </article>

        <article className="panel panel--principles">
          <p className="eyebrow">Boundary guarantees</p>
          <h2>What cannot authorize execution</h2>
          <ul>
            <li>Model output or framework callbacks</li>
            <li>Missing or unverifiable evidence</li>
            <li>Reused or expired authorization</li>
            <li>A REVIEW or BLOCK verdict</li>
          </ul>
          <p className="fineprint">
            Complete mediation still depends on routing every external effect
            through the runtime. Read the repository non-claims before deployment.
          </p>
        </article>
      </section>

      <footer>
        <span>PrivateVault Agent DNA</span>
        <span>Fail closed · Verify independently · Minimize authority</span>
      </footer>
    </main>
  )
}

export default App
