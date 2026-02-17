import { Link, Route, Routes } from 'react-router-dom'
import HomePage from './pages/HomePage'
import LiveScanPage from './pages/LiveScanPage'
import ResultsPage from './pages/ResultsPage'

export default function App() {
  return (
    <div className="app">
      <header>
        <h1>AutoVuln</h1>
        <nav>
          <Link to="/">Home</Link>
        </nav>
      </header>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/scan/:id" element={<LiveScanPage />} />
        <Route path="/results/:id" element={<ResultsPage />} />
      </Routes>
    </div>
  )
}
