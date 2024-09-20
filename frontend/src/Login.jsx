import { useState } from 'react';
import axios from 'axios';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('');

  const handleLogin = async () => {
    try {
      const response = await axios.post('/login', { username, password });
      setRole(response.data.role);
      localStorage.setItem('token', response.data.token);
    } catch (err) {
      console.error(err.response.data.message);
    }
  };

  return (
    <div>
      <input type="text" placeholder="Username" onChange={(e) => setUsername(e.target.value)} />
      <input type="password" placeholder="Password" onChange={(e) => setPassword(e.target.value)} />
      <button onClick={handleLogin}>Login</button>
      <p>{role ? `You are logged in as: ${role}` : ''}</p>
    </div>
  );
};

export default Login;
