import React from 'react';
import { ShieldCheck } from 'lucide-react';
export default function Navbar({logout}){
  return <div className="nav"><div className="brand"><ShieldCheck size={24}/><span>DevSecOps Agent</span></div><div className="links"><a href="#/">Dashboard</a><a href="#/history">History</a><button onClick={logout}>Logout</button></div></div>
}
