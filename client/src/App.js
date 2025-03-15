// client/src/App.js
import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import Materials from './components/Materials';
import Login from './components/Login';
import { useAuthStatus } from './hooks/useAuth';

function App() {
  const { data: authData, isLoading } = useAuthStatus();
  const user = authData?.user || null;

  if (isLoading) {
    return <div className="text-center mt-5">Loading...</div>;
  }

  return (
    <Routes>
      <Route path="/login" element={!user ? <Login /> : <Navigate to="/dashboard" />} />
      <Route path="/dashboard" element={user ? <Dashboard user={user} /> : <Navigate to="/login" />} />
      <Route path="/materials" element={user ? <Materials user={user} /> : <Navigate to="/login" />} />
      <Route path="/" element={<Navigate to="/dashboard" />} />
    </Routes>
  );
}

export default App;