import { useState } from 'react'
import Overview from './pages/Overview.jsx'
import Events from './pages/Events.jsx'
import Alerts from './pages/Alerts.jsx'

const tabs = [
  { id: 'overview', label: 'Overview', component: Overview },
  { id: 'events', label: 'Events', component: Events },
  { id: 'alerts', label: 'Alerts', component: Alerts },
]

export default function App() {
  const [tab, setTab] = useState('overview')
  const Active = tabs.find((t) => t.id === tab).component

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">seclog</span>
        <nav>
          {tabs.map((t) => (
            <button
              key={t.id}
              className={t.id === tab ? 'active' : ''}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </header>
      <main className="content">
        <Active />
      </main>
    </div>
  )
}
