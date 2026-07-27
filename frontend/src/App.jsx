import React, {useEffect, useState} from 'react';
import { clearToken, getToken } from './utils/api';
import Login from './pages/Login.jsx';
import Dashboard from './pages/Dashboard.jsx';
import History from './pages/History.jsx';
import Report from './pages/Report.jsx';
import Navbar from './components/Navbar.jsx';

export default function App(){
  const [token,setTokenState]=useState(getToken());
  const [route,setRoute]=useState(location.hash.replace('#','') || '/');
  useEffect(()=>{ const onHash=()=>setRoute(location.hash.replace('#','')||'/'); window.addEventListener('hashchange',onHash); return()=>window.removeEventListener('hashchange',onHash);},[]);
  const logout=()=>{ clearToken(); setTokenState(null); location.hash='/'; };
  if(!token) return <Login onLogin={()=>setTokenState(getToken())}/>;
  let page = <Dashboard/>;
  if(route.startsWith('/history')) page=<History/>;
  if(route.startsWith('/report/')) page=<Report id={route.split('/').pop()}/>;
  return <><Navbar route={route} logout={logout}/><main className="container">{page}</main></>;
}
