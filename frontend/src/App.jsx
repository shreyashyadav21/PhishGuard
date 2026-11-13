import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';

import Sidebar from './components/Sidebar';
import Navbar from './components/Navbar';
import Overview from './pages/Overview';
import GmailConnection from './pages/GmailConnection';
import Threats from './pages/Threats';
import SecurityReports from './pages/SecurityReports';
import SettingsPage from './pages/SettingsPage';

function Layout({ children }) {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();
  const pageTitles = {
    '/': 'Inbox overview',
    '/gmail-connect': 'Gmail protection',
    '/threats': 'Threats',
    '/reports': 'Reports',
    '/settings': 'Settings',
  };

  return (
    <div className="min-h-screen text-slate-100 selection:bg-[#d5ff72] selection:text-[#101611]">
      <Sidebar collapsed={collapsed} setCollapsed={setCollapsed} />
      <Navbar collapsed={collapsed} pageTitle={pageTitles[location.pathname] || 'PhishGuard'} />

      <main
        className={`min-h-screen px-4 pb-12 pt-20 transition-all duration-300 sm:px-6 ${
          collapsed ? 'ml-20' : 'ml-64'
        }`}
      >
        <div className="mx-auto max-w-7xl">{children}</div>
      </main>

      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#18211a',
            color: '#f3f5e9',
            border: '1px solid rgba(213, 255, 114, 0.2)',
            fontSize: '12px',
            borderRadius: '10px',
          },
        }}
      />
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/gmail-connect" element={<GmailConnection />} />
          <Route path="/threats" element={<Threats />} />
          <Route path="/reports" element={<SecurityReports />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
}
