import { useState, useEffect, useRef, useCallback } from 'react';
import { useScrollReveal } from './hooks/useScrollReveal';
import { SCAN_RESULT } from './data/stubData';
import Navbar from './components/Navbar';
import HeroSection from './components/HeroSection';
import HowItWorks from './components/HowItWorks';
import WhyArgus from './components/WhyArgus';
import DemoPanel from './components/DemoPanel';
import ScanReport from './components/ScanReport';
import BlockchainTrust from './components/BlockchainTrust';
import Footer from './components/Footer';

export default function App() {
  useScrollReveal();
  const [scanActive, setScanActive] = useState(false);
  const [scanComplete, setScanComplete] = useState(false);
  const glowRef = useRef<HTMLDivElement>(null);

  const scrollToDemo = () => {
    document.getElementById('demo')?.scrollIntoView({ behavior: 'smooth' });
    setTimeout(() => setScanActive(true), 600);
  };

  // Grid glow follows mouse
  const handleMouseMove = useCallback((e: MouseEvent) => {
    if (glowRef.current) {
      glowRef.current.style.left = `${e.clientX}px`;
      glowRef.current.style.top = `${e.clientY}px`;
      glowRef.current.style.opacity = '1';
    }
  }, []);

  const handleMouseLeave = useCallback(() => {
    if (glowRef.current) {
      glowRef.current.style.opacity = '0';
    }
  }, []);

  useEffect(() => {
    window.addEventListener('mousemove', handleMouseMove);
    document.body.addEventListener('mouseleave', handleMouseLeave);
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      document.body.removeEventListener('mouseleave', handleMouseLeave);
    };
  }, [handleMouseMove, handleMouseLeave]);

  // Scroll to the dial/results section when scan completes
  useEffect(() => {
    if (scanComplete) {
      setTimeout(() => {
        document.getElementById('demo-results')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 300);
    }
  }, [scanComplete]);

  return (
    <div className="app-grid-bg" style={{ minHeight: '100vh', background: 'var(--bg-void)', position: 'relative' }}>
      <div ref={glowRef} className="grid-glow" style={{ opacity: 0 }} />
      <Navbar onStartScan={scrollToDemo} />
      <HeroSection onStartScan={scrollToDemo} />
      <HowItWorks />
      <WhyArgus />
      <DemoPanel
        scanActive={scanActive}
        onLaunch={() => setScanActive(true)}
        onScanComplete={() => setScanComplete(true)}
      />
      {scanComplete && (
          <ScanReport result={SCAN_RESULT} />
      )}
      <BlockchainTrust />
      <Footer />
    </div>
  );
}
