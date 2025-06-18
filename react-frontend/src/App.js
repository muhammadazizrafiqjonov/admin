// import React, { useEffect, useState } from 'react';
import React, { useState } from 'react';

// function App() {
//   const [msg, setMsg] = useState("");

//   useEffect(() => {
//     fetch("http://127.0.0.1:5000/api/greet")
//       .then(res => res.json())
//       .then(data => setMsg(data.message));
//   }, []);

//   return (
//     <div>
//       <h1>Flaskdan: {msg}</h1>
//     </div>
//   );
// }

const CreateUser = () => {
  const [formData, setFormData] = useState({
    name: '',
    surname: '',
    email: '',
    password: '',
    conf_password: '',
  });

  const [message, setMessage] = useState('');

  const handleChange = (e) => {
    setFormData(prev => ({
      ...prev,
      [e.target.name]: e.target.value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const token = localStorage.getItem('token');

      const response = await fetch('http://localhost:5000/user', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-access-token': token,
        },
        body: JSON.stringify(formData),  // JSON yuborilmoqda
      });

      const data = await response.json();

      if (response.ok) {
        setMessage('Foydalanuvchi yaratildi!');
      } else {
        setMessage(data.message || 'Xatolik yuz berdi.');
      }
    } catch (error) {
      console.error('Error:', error);
      setMessage('Server bilan bog‘lanishda xatolik.');
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input type="text" name="name" placeholder="Ism" onChange={handleChange} required />
      <input type="text" name="surname" placeholder="Familiya" onChange={handleChange} required />
      <input type="email" name="email" placeholder="Email" onChange={handleChange} required />
      <input type="password" name="password" placeholder="Parol" onChange={handleChange} required />
      <input type="password" name="conf_password" placeholder="Parolni tasdiqlash" onChange={handleChange} required />
      <button type="submit">Yaratish</button>
      <p>{message}</p>
    </form>
  );
};

export default CreateUser;
