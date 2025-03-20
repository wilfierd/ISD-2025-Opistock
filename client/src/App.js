// client/src/App.js
import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import Materials from './components/Materials';
import MaterialDetail from './components/MaterialDetail';
import MaterialRequests from './components/MaterialRequests';
import Users from './components/Users';
import Login from './components/Login';
import { useAuthStatus } from './hooks/useAuth';

function App() {
  const { data: authData, isLoading } = useAuthStatus();
  const user = authData?.user || null;
  const isAdmin = user?.role === 'admin' || user?.role === 'quản lý';
  if (isLoading) {
    return <div className="text-center mt-5">Loading...</div>;
  }

  return (
    <Routes>
      <Route path="/login" element={!user ? <Login /> : <Navigate to="/dashboard" />} />
      <Route path="/dashboard" element={user ? <Dashboard user={user} /> : <Navigate to="/login" />} />
      <Route path="/materials" element={user ? <Materials user={user} /> : <Navigate to="/login" />} />
      <Route path="/material/:id" element={user ? <MaterialDetail user={user} /> : <Navigate to="/login" />} />
      
      {/* Restrict employees route to admin users only */}
      <Route 
        path="/employees" 
        element={user && isAdmin ? <Users user={user} /> : <Navigate to="/dashboard" />} 
      />
      
      {/* Admin only routes */}
      <Route 
        path="/requests" 
        element={user && isAdmin ? <MaterialRequests user={user} /> : <Navigate to="/dashboard" />} 
      />
      
      <Route path="/" element={<Navigate to="/dashboard" />} />
    </Routes>
  );
}

export default App;