import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import Dashboard from './components/Dashboard';
import AuditLogPage from './components/AuditLogPage';

const API_BASE = 'http://localhost:5000';

function App() {
  return (
    <Router>
      <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
        <Navbar />
        <main style={{ flex: 1 }}>
          <Routes>
            <Route path="/" element={<Dashboard apiBase={API_BASE} />} />
            <Route path="/audit-logs" element={<AuditLogPage apiBase={API_BASE} />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
