import React from 'react';
import { NavLink } from 'react-router-dom';
import { ShieldCheck, LayoutDashboard, History, LogOut } from 'lucide-react';

const Navbar: React.FC = () => {
  return (
    <nav className="navbar">
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <ShieldCheck color="var(--primary)" size={28} />
        <span style={{ fontSize: '18px', fontWeight: 'bold' }}>VAULT CONTROL</span>
      </div>
      <div className="nav-links">
        <NavLink to="/" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`} end>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <LayoutDashboard size={18} />
            Dashboard
          </div>
        </NavLink>
        <NavLink to="/audit-logs" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <History size={18} />
            Audit Logs
          </div>
        </NavLink>
        <button className="btn btn-ghost" style={{ fontSize: '14px' }}>
          <LogOut size={18} />
          Logout
        </button>
      </div>
    </nav>
  );
};

export default Navbar;
