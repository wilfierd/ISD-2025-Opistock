// client/src/components/Login.js
import React, { useState } from 'react';
import { useLogin } from '../hooks/useAuth';

function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const { login, isLoading, error } = useLogin();

  const handleSubmit = (e) => {
    e.preventDefault();
    login({ username, password });
  };

  return (
    <div className="d-flex align-items-center justify-content-center" style={{ height: '100vh', backgroundColor: '#f5f5f5' }}>
      <div className="login-container" style={{ maxWidth: '400px', padding: '30px', backgroundColor: 'white', borderRadius: '8px', boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)' }}>
        <div className="login-header text-center mb-4">
          <h2 style={{ color: '#0a4d8c' }}>Inventory Management</h2>
          <p>Nhập thông tin đăng nhập của bạn để truy cập hệ thống</p>
        </div>
        
        {error && (
          <div className="alert alert-danger" role="alert">
            {error}
          </div>
        )}
        
        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <label htmlFor="username" className="form-label">Tài khoản</label>
            <input 
              type="text" 
              className="form-control" 
              id="username" 
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required 
            />
          </div>
          <div className="mb-3">
            <label htmlFor="password" className="form-label">Mật khẩu</label>
            <input 
              type="password" 
              className="form-control" 
              id="password" 
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required 
            />
          </div>
          <div className="d-grid gap-2">
            <button 
              type="submit" 
              className="btn btn-primary" 
              disabled={isLoading}
            >
              {isLoading ? 'Logging in...' : 'Login'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default Login;
