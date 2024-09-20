import { useEffect, useState } from 'react';
import jwtDecode from 'jwt-decode';

const Dashboard = () => {
  const [role, setRole] = useState('');

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      const decoded = jwtDecode(token);
      setRole(decoded.role);
    }
  }, []);

  if (role === 'admin') {
    return <div>Welcome Admin</div>;
  } else if (role === 'user') {
    return <div>Welcome User</div>;
  } else {
    return <div>Access Denied</div>;
  }
};

export default Dashboard;
