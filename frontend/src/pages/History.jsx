import React,{useEffect,useState} from 'react';
import { api } from '../utils/api';
export default function History(){
 const [items,setItems]=useState([]),[error,setError]=useState('');
 useEffect(()=>{ api('/api/history').then(d=>setItems(d.items)).catch(e=>setError(e.message));},[]);
 return <div><h1>Inspection History</h1>{error&&<div className="error">{error}</div>}<div className="table">{items.map(x=><a className="row" href={`#/report/${x.id}`} key={x.id}><span>#{x.id}</span><span>{x.host_name||'pending'}</span><span>{x.containers_scanned} containers</span><span>{x.issues_found} issues</span><span className={`badge ${x.risk_level}`}>{x.risk_level||x.status}</span></a>)}</div></div>
}
