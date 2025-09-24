// src/App.js
import {useState} from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import ProtectedRoute from './components/utils/ProtectedRoute';
import Login from './views/Login';
import Register from './views/Register';

import Dashboard from './views/Dashboard';

const App = () => {
  const [user, setUser] = useState(getStoredUser);
  return (
    <Router>
      <Routes>
        {/* Ruta principal protegida - Redirige a dashboard si está autenticado */}

        <Route element={<ProtectedRoute canActivate={user} redirectPath='/login' />}>
          <Route path="" element={<Dashboard />} />
        </Route>
        {/* Ruta de login - No accesible si ya está autenticado */}
        <Route element={<ProtectedRoute canActivate={!user} redirectPath='/' />}>
          <Route
            path="login"
            element={
              <Login />
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
function getStoredUser() {
  try {
    const storedUser = localStorage.getItem('user');
    // Parse the JSON data if it exists; otherwise, return null.
    return storedUser ? JSON.parse(storedUser) : null;
  } catch (error) {
    console.error("Failed to parse user data from localStorage", error);
    return null;
  }
}

export default App;