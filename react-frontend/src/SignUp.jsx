import { useState } from "react";
import axios from "axios";

export default function SignUp() {
  const [form, setForm] = useState({
    name: "",
    surname: "",
    email: "",
    password: "",
    conf_password: "",
  });

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    console.log(form);
    
    e.preventDefault();
    try {
      const res = await axios.post("http://localhost:4200/sign-up", form);
      alert(res.data.message);
    } catch (err) {
      alert(err.response.data.message);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input name="name" placeholder="Ism" onChange={handleChange} />
      <input name="surname" placeholder="Familiya" onChange={handleChange} />
      <input name="email" type="email" placeholder="Email" onChange={handleChange} />
      <input name="password" type="password" placeholder="Parol" onChange={handleChange} />
      <input name="conf_password" type="password" placeholder="Parolni tasdiqlang" onChange={handleChange} />
      <button type="submit">Ro'yhatdan o'tish</button>
    </form>
  );
}
