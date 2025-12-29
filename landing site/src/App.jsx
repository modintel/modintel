import React from 'react';
import Navbar from './components/Navbar';
import Hero from './components/Hero';
import Features from './components/Features';
import HowItWorks from './components/HowItWorks';
import './App.css';

function App() {
  return (
    <div className="app">
      <Navbar />
      <Hero />
      <Features />
      <HowItWorks />

      {/* Footer Placeholder */}
      <div style={{
        padding: '60px 0',
        textAlign: 'center',
        borderTop: '1px solid rgba(255,255,255,0.05)',
        background: 'var(--bg-dark)'
      }}>
        <p style={{ color: 'var(--text-gray)', fontSize: '0.9rem' }}>© 2025 ModIntel. All rights reserved.</p>
      </div>
    </div>
  );
}

export default App;
