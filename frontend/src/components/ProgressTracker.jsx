import React from 'react';
export default function ProgressTracker({items}){ return <div className="progress">{items.map((x,i)=><div key={i} className="progress-item">✓ {x}</div>)}</div> }
