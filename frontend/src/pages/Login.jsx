import React,{useState} from 'react';
import { api, setToken } from '../utils/api';

export default function Login({onLogin}){
  const [mode,setMode]=useState('login');
  const [email,setEmail]=useState('admin@example.com');
  const [password,setPassword]=useState('hello123');
  const [error,setError]=useState('');
  async function submit(e){
    e.preventDefault(); setError('');
    try{ const data=await api(`/api/auth/${mode}`,{method:'POST',body:JSON.stringify({email,password})}); setToken(data.token); onLogin(); }
    catch(err){ setError(err.message); }
  }
  return <div className="login-page">
    <div className="login-shell">
      <div className="login-card">
        <div className="terminal-status">Secure scanner ready</div>
        <div className="pill">AI Powered Scanner</div>
        <h1>DevSecOps Agent</h1>
        <p>Inspect Docker containers, image vulnerabilities, cloud posture, and runtime issues with AI-powered recommendations.</p>
        <form onSubmit={submit}>
          <input value={email} onChange={e=>setEmail(e.target.value)} placeholder="Email"/>
          <input type="password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="Password"/>
          <button>{mode==='login'?'Login':'Create account'}</button>
        </form>
        {error&&<div className="error">{error}</div>}
        <button className="linkbtn" onClick={()=>setMode(mode==='login'?'signup':'login')}>{mode==='login'?'Need an account? Sign up':'Already have an account? Login'}</button>
      </div>

      <div className="ai-explainer-card">
        <div className="pill">AI Analyst Layer</div>
        <h2>What AI does here</h2>
        <p><strong>AI in DevSecOps Agent</strong> turns raw scan data into an engineer-friendly security report.</p>
        <h3>It helps with:</h3>
        <ol>
          <li>Summarizing Docker, Trivy, and cloud scan results</li>
          <li>Explaining risks in simple language</li>
          <li>Prioritizing issues as Critical, High, Medium, or Low</li>
          <li>Suggesting remediation steps</li>
          <li>Converting technical findings into an action plan</li>
        </ol>
        <div className="compare-block">
          <span>Instead of only showing:</span>
          <pre>{`Container is privileged
Port 0.0.0.0:8080 exposed
Image has 12 HIGH vulnerabilities
S3 bucket may allow public access`}</pre>
        </div>
        <div className="ai-output-block">
          <span>AI explains:</span>
          <p>This environment has a high security risk because one container is running with privileged access, a service is publicly exposed, and the image contains high-severity vulnerabilities. First, remove privileged mode, restrict the exposed port, and rebuild the image with patched dependencies.</p>
        </div>
      </div>
    </div>
  </div>
}
