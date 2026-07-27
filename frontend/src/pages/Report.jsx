import React,{useEffect,useState} from 'react';
import { api } from '../utils/api';
import CodeBlock from '../components/CodeBlock.jsx';

export default function Report({id}){
 const [item,setItem]=useState(null),[error,setError]=useState('');
 useEffect(()=>{ api(`/api/inspections/${id}`).then(setItem).catch(e=>setError(e.message));},[id]);
 if(error) return <div className="error">{error}</div>;
 if(!item) return <div className="panel">Loading report...</div>;
 const analysis=item.result.analysis||{}, scan=item.result.scan||{};
 const trivy=scan.trivy||{}; const sev=trivy.summary?.severity_counts||{}; const cloud=scan.cloud||{};
 const inventory=cloud.inventory||{};
 const localSummary=scan.summary||{};
 const ecsSummary=inventory.ecs_summary||null;
 const ecrSummary=inventory.ecr_summary||null;
 const ec2DockerSummary=inventory.ec2_docker_summary||null;
 const localSkipped=scan.host?.host_name==='local-docker-scan-skipped' || scan.host?.host_name==='cloud-container-scan-only';
 const cloudEnabled=Boolean(cloud.enabled);
 const issueCount=analysis.issues?.length||0;
 const reportCards=buildReportCards({localSkipped,localSummary,cloudEnabled,ecsSummary,ecrSummary,ec2DockerSummary,issueCount});
 const summaryText=buildSummaryText({localSkipped,localSummary,cloud,ecsSummary,ecrSummary,ec2DockerSummary,issueCount,analysis});
 return <div>
  <div className="hero">
   <div>
    <div className={`pill risk-${analysis.risk_level}`}>Risk: {analysis.risk_level}</div>
    <h1>Inspection Report #{item.id}</h1>
    <p>{summaryText}</p>
   </div>
   <a className="secondary-btn" href="#/dashboard">Back to Dashboard</a>
  </div>

  <div className="grid">{reportCards.map((card,i)=><Card key={`${card.title}-${i}`} title={card.title} value={card.value}/>)}</div>

  {cloud.enabled&&<div className="panel"><h2>{String(cloud.provider||'Cloud').toUpperCase()} Cloud Security Scan</h2><div className="grid"><Card title="Cloud Risk" value={cloud.risk_level}/><Card title="Cloud Issues" value={cloud.summary?.issues||0}/><Card title="Critical Cloud Issues" value={cloud.summary?.critical||0}/><Card title="High Cloud Issues" value={cloud.summary?.high||0}/>{ec2DockerSummary&&<Card title="EC2 Docker Containers" value={ec2DockerSummary.containers||0}/>} {ecsSummary&&<Card title="ECS Tasks" value={ecsSummary.tasks||0}/>} {ecrSummary&&<Card title="ECR Images" value={ecrSummary.images||0}/>}</div>{ecsSummary&&<CloudEcs inventory={inventory}/>} {ecrSummary&&<CloudEcr inventory={inventory}/>} {ec2DockerSummary&&<CloudEc2Docker inventory={inventory}/>}<h3>Cloud Findings</h3><div className="table">{(cloud.issues||[]).map((issue,i)=><div className="row" key={i}><span>{issue.title}</span><span>{issue.resource}</span><span className={`badge ${issue.severity}`}>{issue.severity}</span><span>{issue.reason}</span></div>)}</div></div>}

  {trivy.enabled&&<div className="panel"><h2>Trivy Security Scan</h2>{trivy.available===false?<p>{trivy.message}</p>:<><div className="grid"><Card title="Images Scanned" value={trivy.images_scanned}/><Card title="Critical" value={sev.CRITICAL||0}/><Card title="High" value={sev.HIGH||0}/><Card title="Secrets" value={trivy.summary?.secrets||0}/></div><div className="table">{(trivy.images||[]).map((img,i)=><div className="row" key={i}><span>{img.image}</span><span>{img.status}</span><span>{img.summary?.vulnerabilities||0} vulns</span><span>{img.summary?.secrets||0} secrets</span></div>)}</div></>}</div>}

  <div className="panel"><h2>Findings</h2>{(analysis.issues||[]).map((issue,i)=><div className="issue" key={i}><div><b>{issue.title}</b><span className={`badge ${issue.severity}`}>{issue.severity}</span></div><p>{issue.resource}: {issue.reason}</p><CodeBlock>{issue.suggested_command}</CodeBlock></div>)}</div>

  {!localSkipped&&<div className="panel"><h2>Local Docker Containers</h2><div className="table">{(scan.containers||[]).map(c=><div className="row" key={c.full_id}><span>{c.name}</span><span>{c.image}</span><span>{c.status}</span><span>Health: {c.health || 'not configured'}</span><span>Exit: {c.exit_code ?? '-'}</span></div>)}</div></div>}
 </div>
}
function Card({title,value}){ return <div className="card"><span>{title}</span><strong>{value ?? 0}</strong></div> }

function buildReportCards({localSkipped,localSummary,cloudEnabled,ecsSummary,ecrSummary,ec2DockerSummary,issueCount}){
 const cards=[];
 if(!localSkipped){
  cards.push({title:'Local Docker Containers',value:localSummary?.containers_scanned||0});
  cards.push({title:'Local Running Containers',value:localSummary?.running||0});
  cards.push({title:'Local Stopped Containers',value:localSummary?.stopped ?? localSummary?.exited ?? 0});
 }
 if(cloudEnabled&&ec2DockerSummary){
  cards.push({title:'AWS EC2 Docker Containers',value:ec2DockerSummary.containers||0});
  cards.push({title:'AWS EC2 Docker Running',value:ec2DockerSummary.running||0});
  cards.push({title:'AWS EC2 Docker Stopped',value:ec2DockerSummary.stopped||0});
 }
 if(cloudEnabled&&ecsSummary){
  cards.push({title:'AWS ECS Tasks',value:ecsSummary.tasks||0});
  cards.push({title:'AWS ECS Running Tasks',value:ecsSummary.running_tasks||0});
 }
 if(cloudEnabled&&ecrSummary){
  cards.push({title:'AWS ECR Images',value:ecrSummary.images||0});
 }
 if(cards.length===0){
  cards.push({title:'Containers',value:localSummary?.containers_scanned||0});
  cards.push({title:'Running',value:localSummary?.running||0});
  cards.push({title:'Stopped',value:localSummary?.stopped ?? localSummary?.exited ?? 0});
 }
 cards.push({title:'Total Findings',value:issueCount});
 return cards;
}

function buildSummaryText({localSkipped,localSummary,cloud,ecsSummary,ecrSummary,ec2DockerSummary,issueCount,analysis}){
 const parts=[];
 if(!localSkipped){
  parts.push(`Local Docker scan found ${localSummary?.containers_scanned||0} container(s): ${localSummary?.running||0} running and ${localSummary?.stopped ?? localSummary?.exited ?? 0} stopped.`);
 }else{
  parts.push('Local Docker scan was skipped.');
 }
 if(cloud?.enabled){
  if(ec2DockerSummary){
   parts.push(`AWS EC2 Docker via SSM found ${ec2DockerSummary.containers||0} container(s) across ${ec2DockerSummary.instances||0} EC2 instance(s): ${ec2DockerSummary.running||0} running and ${ec2DockerSummary.stopped||0} stopped.`);
  }
  if(ecsSummary){
   parts.push(`AWS ECS inventory found ${ecsSummary.tasks||0} task(s) across ${ecsSummary.services||0} service(s).`);
  }
  if(ecrSummary){
   parts.push(`AWS ECR inventory found ${ecrSummary.images||0} image(s) across ${ecrSummary.repositories||0} repository/repositories.`);
  }
  parts.push(`Cloud security scan found ${cloud.summary?.issues||0} cloud issue(s).`);
 }
 if(parts.length===0 && analysis.executive_summary) return analysis.executive_summary;
 return `${parts.join(' ')} Total findings: ${issueCount}. Review security, reliability, and cleanup recommendations before taking action.`;
}

function CloudEcs({inventory}){
 const services=inventory.ecs_services||[]; const tasks=inventory.ecs_tasks||[]; const summary=inventory.ecs_summary||{};
 return <div className="cloud-detail"><h3>AWS ECS Containers</h3><p className="muted">Clusters: {summary.clusters||0} · Services: {summary.services||0} · Running tasks: {summary.running_tasks||0} · Stopped tasks: {summary.stopped_tasks||0}</p><div className="table">{services.slice(0,20).map((svc,i)=><div className="row" key={i}><span>{svc.region}/{svc.cluster_name}</span><span>{svc.service_name}</span><span>Desired: {svc.desired_count}</span><span>Running: {svc.running_count}</span></div>)}</div><h4>ECS Tasks</h4><div className="table">{tasks.slice(0,30).map((task,i)=><div className="row" key={i}><span>{task.region}/{task.cluster_name}</span><span>{task.task_id}</span><span>{task.last_status}</span><span>{(task.containers||[]).map(c=>`${c.name}:${c.last_status}`).join(', ')}</span></div>)}</div></div>
}
function CloudEcr({inventory}){
 const repos=inventory.ecr_repositories||[]; const images=inventory.ecr_images||[]; const summary=inventory.ecr_summary||{};
 return <div className="cloud-detail"><h3>AWS ECR Images</h3><p className="muted">Repositories: {summary.repositories||0} · Images checked: {summary.images||0} · Critical: {summary.critical||0} · High: {summary.high||0}</p><div className="table">{repos.slice(0,20).map((repo,i)=><div className="row" key={i}><span>{repo.region}</span><span>{repo.repository_name}</span><span>{repo.scan_on_push?'Scan on push':'Scan on push off'}</span><span>{repo.uri}</span></div>)}</div><h4>ECR Image Findings</h4><div className="table">{images.slice(0,30).map((img,i)=><div className="row" key={i}><span>{img.region}/{img.repository_name}</span><span>{(img.image_tags||[]).join(', ')||String(img.image_digest||'').slice(0,18)}</span><span>Critical: {img.severity_counts?.CRITICAL||0}</span><span>High: {img.severity_counts?.HIGH||0}</span></div>)}</div></div>
}

function CloudEc2Docker({inventory}){
 const summary=inventory.ec2_docker_summary||{}; const containers=inventory.ec2_docker_containers||[]; const instances=inventory.ec2_docker_instances||[];
 return <div className="cloud-detail"><h3>AWS EC2 Docker Containers via SSM</h3><p className="muted">Instances scanned: {summary.instances||0} · Containers: {summary.containers||0} · Running: {summary.running||0} · Stopped: {summary.stopped||0} · Remote Trivy images: {summary.trivy_images_scanned||0}</p><div className="table">{instances.slice(0,20).map((inst,i)=><div className="row" key={i}><span>{inst.region}/{inst.instance_id}</span><span>{inst.host_name||'unknown host'}</span><span>{inst.ssm_status}</span><span>{inst.docker_available?'Docker available':'Docker unavailable'}</span></div>)}</div><h4>Remote Docker Containers</h4><div className="table">{containers.slice(0,50).map((c,i)=><div className="row" key={i}><span>{c.region}/{c.instance_id}</span><span>{c.name}</span><span>{c.image}</span><span>{c.status} · Exit: {c.exit_code ?? '-'}</span></div>)}</div></div>
}
