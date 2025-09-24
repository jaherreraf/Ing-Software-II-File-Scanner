// src/App.js
import {useState} from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import ProtectedRoute from './components/utils/ProtectedRoute';
import Login from './views/Login';
import Register from './views/Register';

import Dashboard from './views/Dashboard';

function getStoredUser() {
  try {
    const user = localStorage.getItem('user');
    return user ? JSON.parse(user) : null;
  } catch {
    return null;
  }
}

const App = () => {
  const [user, setUser] = useState(getStoredUser());
  return (
    <Router>
      <Routes>
        {/* Ruta principal protegida - Redirige a dashboard si está autenticado */}
        <Route element={<ProtectedRoute canActivate={user} redirectPath='/login' />}>
          <Route path="" element={<Dashboard setUser={setUser} />} />
        </Route>
        {/* Ruta de login - No accesible si ya está autenticado */}
        <Route element={<ProtectedRoute canActivate={!user} redirectPath='/' />}>
          <Route
            path="login"
            element={
              <Login setUser={setUser} />
            }
          />
        </Route>
        <Route element={<ProtectedRoute canActivate={!user} redirectPath='/' />}>
        <Route
          path="register"
          element={
            <Register />
          }
        />
        </Route>
        

        {/* Ruta de fallback para URLs no encontradas */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
};

export default App;