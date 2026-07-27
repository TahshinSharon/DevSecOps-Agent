import React,{useEffect,useState} from 'react';
import { api, wsUrl } from '../utils/api';
import ProgressTracker from '../components/ProgressTracker.jsx';
import CodeBlock from '../components/CodeBlock.jsx';

const defaultCloud = {
  enabled:false,
  provider:'aws',
  services:['ecs','ecr','security_groups','s3','iam'],
  regions:['us-east-1'],
  aws:{access_key_id:'',secret_access_key:'',session_token:'',region:'us-east-1',ec2_instance_ids:[],install_trivy_on_ec2:false},
  gcp:{project_id:'',service_account_json:''},
  azure:{tenant_id:'',client_id:'',client_secret:'',subscription_id:''}
};
const defaultAi = {enabled:false,api_key:'',model:'gpt-4o-mini',base_url:''};
const cloudCards = [
  {provider:'aws', name:'AWS', image:'/cloud/aws.svg', subtitle:'ECS, ECR, EC2 Docker, S3, IAM'},
  {provider:'gcp', name:'GCP', image:'/cloud/gcp.svg', subtitle:'Firewall, Storage'},
  {provider:'azure', name:'Azure', image:'/cloud/azure.svg', subtitle:'NSG, Storage'}
];

export default function Dashboard(){
 const [error,setError]=useState(''),[progress,setProgress]=useState([]),[running,setRunning]=useState(false);
 const [latestInspection,setLatestInspection]=useState(()=>{try{return JSON.parse(sessionStorage.getItem('devsecops_latest_inspection')||'null')}catch{return null}});
 const [scanMode,setScanMode]=useState(()=>sessionStorage.getItem('devsecops_scan_mode') || 'local');
 const [selectedContainerId,setSelectedContainerId]=useState('');
 const [diagnostics,setDiagnostics]=useState(null);
 const [diagnosticsLoading,setDiagnosticsLoading]=useState(false);
 const [diagnosticsError,setDiagnosticsError]=useState('');
 const [awsRegions,setAwsRegions]=useState(['us-east-1']);
 const [regionsLoading,setRegionsLoading]=useState(false);
 const [regionsError,setRegionsError]=useState('');
 const [ec2Instances,setEc2Instances]=useState([]);
 const [ec2Loading,setEc2Loading]=useState(false);
 const [ec2Error,setEc2Error]=useState('');
 const [ec2Info,setEc2Info]=useState('');
 const [opts,setOpts]=useState({enable_docker:true,include_stats:true,include_logs:false,log_tail:80,only_running:false,enable_trivy:false,trivy_scanners:'vuln,secret',trivy_severity:'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',trivy_max_images:20,trivy_timeout_seconds:180,ai:defaultAi,cloud:defaultCloud});
 const scan=latestInspection?.result?.scan || null;
 const cloud=scan?.cloud || null;

 useEffect(()=>{ sessionStorage.setItem('devsecops_scan_mode', scanMode); },[scanMode]);
 function selectMode(mode){
   setScanMode(mode);
   if(mode==='local') setOpts(o=>({...o, enable_docker:true, cloud:{...o.cloud, enabled:false}}));
   else setOpts(o=>({...o, enable_docker:false, cloud:{...o.cloud, enabled:true, provider:o.cloud.provider||'aws'}}));
 }
 function updateCloud(patch){ setOpts(o=>({...o, cloud:{...o.cloud, ...patch}})); }
 function updateAi(patch){ setOpts(o=>({...o, ai:{...o.ai, ...patch}})); }
 function updateProvider(provider){
   const services = provider==='aws' ? ['ecs','ecr','security_groups','s3','iam'] : provider==='gcp' ? ['firewall','storage'] : ['nsg','storage'];
   const regions = provider==='aws' ? [opts.cloud.aws.region || 'us-east-1'] : [];
   updateCloud({provider, services, regions});
   setRegionsError(''); setEc2Error(''); setEc2Info(''); setEc2Instances([]);
 }
 function toggleService(service){
   const exists=opts.cloud.services.includes(service);
   updateCloud({services: exists ? opts.cloud.services.filter(s=>s!==service) : [...opts.cloud.services, service]});
 }
 function setRegionText(value){ updateCloud({regions:value.split(',').map(v=>v.trim()).filter(Boolean)}); }
 function toggleAwsRegion(region){
   const exists=opts.cloud.regions.includes(region);
   updateCloud({regions: exists ? opts.cloud.regions.filter(r=>r!==region) : [...opts.cloud.regions, region]});
 }
 function selectAllAwsRegions(){ updateCloud({regions:awsRegions}); }
 function clearAwsRegions(){ updateCloud({regions:[]}); }
 function setCred(provider,key,value){
   updateCloud({[provider]:{...opts.cloud[provider],[key]:value}});
   if(provider==='aws' && key==='region' && !opts.cloud.regions.length){ updateCloud({regions:[value || 'us-east-1']}); }
 }
 function toggleEc2Instance(instance){
   const key=`${instance.region}:${instance.instance_id}`;
   const current=opts.cloud.aws.ec2_instance_ids || [];
   const next=current.includes(key) ? current.filter(v=>v!==key) : [...current,key];
   setCred('aws','ec2_instance_ids',next);
 }
 async function loadAwsRegionList(){
   setRegionsError('');
   const aws=opts.cloud.aws;
   if(!aws.access_key_id || !aws.secret_access_key){ setRegionsError('Provide Access key ID and Secret access key first.'); return; }
   setRegionsLoading(true);
   try{
     const data=await api('/api/cloud/aws/regions',{method:'POST',body:JSON.stringify(aws)});
     const regions=data.regions || [];
     setAwsRegions(regions);
     // Select all loaded regions by default so users do not accidentally search only us-east-1
     // while their EC2 instances live in another region such as us-west-2.
     updateCloud({regions: regions.length ? regions : [aws.region || 'us-east-1']});
   }catch(e){ setRegionsError(e.message); if(e.message.toLowerCase().includes('session') || e.message.toLowerCase().includes('unauthorized')) setError('Your login session is invalid or expired. Please refresh and log in again.'); }
   finally{ setRegionsLoading(false); }
 }
 async function loadEc2InstanceList(){
   setEc2Error(''); setEc2Info(''); setEc2Instances([]);
   const aws=opts.cloud.aws;
   if(!aws.access_key_id || !aws.secret_access_key){ setEc2Error('Provide AWS credentials first.'); return; }
   const regions=opts.cloud.regions?.length ? opts.cloud.regions : (awsRegions.length ? awsRegions : [aws.region || 'us-east-1']);
   setEc2Loading(true);
   try{
     const data=await api('/api/cloud/aws/instances',{method:'POST',body:JSON.stringify({...aws, regions})});
     const instances=data.instances || [];
     setEc2Instances(instances);
     const searched=(data.searched_regions || regions).join(', ');
     if(instances.length===0){
       setEc2Info(`No EC2 instances were found in the selected regions: ${searched}. Make sure the EC2 instance is in one of these regions and the AWS key has ec2:DescribeInstances permission.`);
     }else{
       const managedInstances=instances.filter(i=>i.ssm_managed);
       const managed=managedInstances.length;
       const autoSelected=managedInstances.map(i=>`${i.region}:${i.instance_id}`);
       // Loading instances should be enough for the normal classroom/demo flow.
       // Auto-select SSM-managed instances so users do not accidentally run an EC2 Docker scan with zero targets.
       setOpts(o=>({...o, cloud:{...o.cloud, aws:{...o.cloud.aws, ec2_instance_ids:autoSelected}}}));
       setEc2Info(`Loaded ${instances.length} EC2 instance(s) from ${searched}. ${managed} are SSM managed and were auto-selected for Docker scanning.`);
     }
   }catch(e){ setEc2Error(e.message); }
   finally{ setEc2Loading(false); }
 }
 async function loadDiagnostics(containerId){
   setSelectedContainerId(containerId); setDiagnostics(null); setDiagnosticsError('');
   if(!containerId) return;
   setDiagnosticsLoading(true);
   try{ setDiagnostics(await api(`/api/containers/${encodeURIComponent(containerId)}/diagnostics?tail=250`)); }
   catch(e){ setDiagnosticsError(e.message); }
   finally{ setDiagnosticsLoading(false); }
 }
 async function run(){
  setError(''); setProgress([]); setRunning(true); setLatestInspection(null); setSelectedContainerId(''); setDiagnostics(null); setDiagnosticsError('');
  sessionStorage.removeItem('devsecops_latest_inspection');
  try{
    const payload={...opts, ai:{...opts.ai}, cloud:{...opts.cloud, aws:{...opts.cloud.aws}}};
    if(scanMode==='local'){
      payload.enable_docker=true;
      payload.cloud={...payload.cloud, enabled:false};
    }else{
      payload.enable_docker=false;
      payload.cloud={...payload.cloud, enabled:true};
      if(payload.cloud.provider==='aws' && payload.cloud.regions.length===0) payload.cloud.regions=[payload.cloud.aws.region || 'us-east-1'];
      if(payload.cloud.provider==='aws'){
        // Safety net: if EC2 instances are selected, always run the AWS EC2 Docker SSM scanner.
        // This prevents the UI from loading/selecting EC2 instances but then only running ECS/ECR/security checks.
        const selectedTargets = payload.cloud.aws.ec2_instance_ids || [];
        if(selectedTargets.length>0 && !payload.cloud.services.includes('ec2_docker')){
          payload.cloud.services=[...payload.cloud.services,'ec2_docker'];
        }
      }
    }
    if(payload.cloud?.enabled && payload.cloud.provider==='aws' && payload.cloud.services.includes('ec2_docker') && (!payload.cloud.aws.ec2_instance_ids || payload.cloud.aws.ec2_instance_ids.length===0)){
      throw new Error('AWS EC2 Docker via SSM is enabled, but no SSM-managed EC2 instance is selected. Click Load EC2 Instances and select at least one SSM-managed instance.');
    }
    if(!payload.ai.enabled) payload.ai={enabled:false,api_key:'',model:'',base_url:''};
    const start=await api('/api/inspect',{method:'POST',body:JSON.stringify(payload)});
    const ws=new WebSocket(wsUrl(`/ws/progress/${start.inspection_id}`));
    ws.onmessage=async (event)=>{
      const msg=JSON.parse(event.data).message;
      setProgress(p=>[...p,msg]);
      if(msg.includes('Inspection complete')){
        setRunning(false); ws.close();
        try{ const item=await api(`/api/inspections/${start.inspection_id}`); setLatestInspection(item); sessionStorage.setItem('devsecops_latest_inspection', JSON.stringify(item)); }catch(e){ setError(e.message); }
      }
      if(msg.includes('Inspection failed')) setRunning(false);
    };
    ws.onerror=()=>setError('WebSocket connection failed. The inspection may still be running. Check backend logs if progress does not update.');
  }catch(e){ setRunning(false); setError(e.message); }
 }
 return <div>
   <div className="hero"><div><div className="pill">AI Powered Scanner</div><h1>DevSecOps Agent</h1><p>Interactive container, image, and cloud security scanner — inspect each layer without running Docker or cloud CLI commands.</p><div className="pipeline"><span>Local Docker Runtime</span><span>AWS EC2 Docker via SSM</span><span>AWS ECS/ECR</span><span>AI Findings</span></div></div><button disabled={running} onClick={run}>{running?'Scanning...':'Run Inspection'}</button></div>
   {error&&<div className="error">{error}</div>}
   <ScanModePicker scanMode={scanMode} onSelect={selectMode}/>
   {running&&<ScanSpinner scanMode={scanMode} trivy={opts.enable_trivy} cloud={opts.cloud}/>} 
   {scan&&<Stats scan={scan} cloud={cloud}/>} 
   {scanMode==='local'?<LocalOptions opts={opts} setOpts={setOpts}/>:<CloudOptions opts={opts} setOpts={setOpts} updateCloud={updateCloud} updateProvider={updateProvider} toggleService={toggleService} setCred={setCred} updateAi={updateAi} awsRegions={awsRegions} regionsLoading={regionsLoading} regionsError={regionsError} loadAwsRegionList={loadAwsRegionList} toggleAwsRegion={toggleAwsRegion} selectAllAwsRegions={selectAllAwsRegions} clearAwsRegions={clearAwsRegions} setRegionText={setRegionText} ec2Instances={ec2Instances} ec2Loading={ec2Loading} ec2Error={ec2Error} ec2Info={ec2Info} loadEc2InstanceList={loadEc2InstanceList} toggleEc2Instance={toggleEc2Instance}/>} 
   {progress.length>0&&<ProgressTracker items={progress}/>} 
   {scan?.containers?.length>0&&<ContainerExplorer containers={scan.containers||[]} selectedContainerId={selectedContainerId} diagnostics={diagnostics} diagnosticsLoading={diagnosticsLoading} diagnosticsError={diagnosticsError} onSelect={loadDiagnostics} reportId={latestInspection?.id}/>} 
   {cloud?.inventory?.ec2_docker_containers?.length>0&&<CloudEc2DockerExplorer containers={cloud.inventory.ec2_docker_containers} instances={cloud.inventory.ec2_docker_instances||[]} reportId={latestInspection?.id} aws={opts.cloud.aws} logTail={opts.log_tail}/>} 
  </div>
}
function ScanModePicker({scanMode,onSelect}){return <div className="mode-grid"><button type="button" className={`mode-card ${scanMode==='local'?'selected':''}`} onClick={()=>onSelect('local')}><span className="mode-check">✓</span><b>Local Container Inspection</b><small>Scan Docker containers on the machine where DevSecOps Agent is running. Includes local Trivy and AI analysis.</small></button><button type="button" className={`mode-card ${scanMode==='cloud'?'selected':''}`} onClick={()=>onSelect('cloud')}><span className="mode-check">✓</span><b>Cloud Container Inspection</b><small>Scan AWS ECS/ECR and plain Docker containers inside EC2 using Systems Manager. Includes remote Trivy and AI analysis.</small></button></div>}
function ScanSpinner({scanMode,trivy,cloud}){return <div className="scan-spinner-panel"><div className="spinner"></div><div><h3>Scanning in progress...</h3><p>{scanMode==='local'?'Checking local Docker runtime, containers, images, logs, and health signals.':'Checking selected cloud resources, EC2/ECS/ECR container inventory, and posture findings.'}</p><div className="spinner-steps"><span>Runtime</span>{trivy&&<span>Trivy</span>}{cloud.enabled&&<span>Cloud</span>}<span>AI report</span></div></div></div>}
function Stats({scan,cloud}){const ecs=cloud?.inventory?.ecs_summary||{}; const ecr=cloud?.inventory?.ecr_summary||{}; const ec2d=cloud?.inventory?.ec2_docker_summary||{}; return <div className="grid"><Card title={scan.docker_enabled===false?'Local Docker Scan':'Host'} value={scan.docker_enabled===false?'Skipped':scan.host?.host_name}/><Card title="Running Containers" value={(scan.summary?.running||0)+(ec2d.running||0)}/><Card title="Stopped Containers" value={(scan.summary?.stopped||0)+(ec2d.stopped||0)}/><Card title="Disk Used" value={scan.docker_enabled===false?'N/A':`${scan.host?.disk_percent ?? 0}%`}/>{cloud?.enabled&&<><Card title="AWS ECS Tasks" value={ecs.tasks||0}/><Card title="AWS ECR Images" value={ecr.images||0}/><Card title="AWS EC2 Docker Containers" value={ec2d.containers||0}/><Card title="Cloud Issues" value={cloud.summary?.issues||0}/></>}</div>}
function LocalOptions({opts,setOpts}){return <div className="panel"><h2>Local Container Inspection</h2><ContainerScanOptions opts={opts} setOpts={setOpts} context="local"/><TrivyOptions opts={opts} setOpts={setOpts} context="local"/><AiOptions opts={opts} setOpts={setOpts}/></div>}
function ContainerScanOptions({opts,setOpts,context}){return <div className="nested-options"><h3>{context==='cloud'?'Cloud container runtime options':'Local container runtime options'}</h3><p className="muted">{context==='cloud'?'These options apply to AWS EC2 Docker via SSM. ECS/ECR inventory is still collected through AWS APIs.':'These options apply to the local Docker socket scan.'}</p><label><input type="checkbox" checked={opts.include_stats} onChange={e=>setOpts(o=>({...o,include_stats:e.target.checked}))}/> Include CPU/memory stats</label><label><input type="checkbox" checked={opts.include_logs} onChange={e=>setOpts(o=>({...o,include_logs:e.target.checked}))}/> Include recent container logs</label>{opts.include_logs&&<label>Number of log trail lines<input type="number" min="1" max="500" value={opts.log_tail} onChange={e=>setOpts(o=>({...o,log_tail:Number(e.target.value)||80}))}/></label>}<label><input type="checkbox" checked={opts.only_running} onChange={e=>setOpts(o=>({...o,only_running:e.target.checked}))}/> Only scan running containers</label></div>}
function CloudOptions(props){const {opts,setOpts,updateCloud,updateProvider,toggleService,setCred,awsRegions,regionsLoading,regionsError,loadAwsRegionList,toggleAwsRegion,selectAllAwsRegions,clearAwsRegions,setRegionText,ec2Instances,ec2Loading,ec2Error,ec2Info,loadEc2InstanceList,toggleEc2Instance}=props;return <div><div className="panel"><h2>Cloud Container Inspection</h2><p className="muted">Choose one cloud provider. AWS is selected by default. For plain Docker containers inside EC2, select <b>AWS EC2 Docker via SSM</b>, load instances, and choose your target EC2 machines.</p><div className="cloud-picker">{cloudCards.map(card=><CloudCard key={card.provider} {...card} selected={opts.cloud.provider===card.provider} onClick={()=>updateProvider(card.provider)}/>)}</div>{opts.cloud.provider==='aws'&&<AwsForm cloud={opts.cloud} awsRegions={awsRegions} regionsLoading={regionsLoading} regionsError={regionsError} loadAwsRegionList={loadAwsRegionList} toggleAwsRegion={toggleAwsRegion} selectAllAwsRegions={selectAllAwsRegions} clearAwsRegions={clearAwsRegions} toggleService={toggleService} setRegionText={setRegionText} setCred={setCred} ec2Instances={ec2Instances} ec2Loading={ec2Loading} ec2Error={ec2Error} ec2Info={ec2Info} loadEc2InstanceList={loadEc2InstanceList} toggleEc2Instance={toggleEc2Instance}/>} {opts.cloud.provider==='gcp'&&<GcpForm cloud={opts.cloud} toggleService={toggleService} setCred={setCred}/>} {opts.cloud.provider==='azure'&&<AzureForm cloud={opts.cloud} toggleService={toggleService} setCred={setCred}/>}</div><div className="panel"><h2>Cloud Scan Add-ons</h2><ContainerScanOptions opts={opts} setOpts={setOpts} context="cloud"/><TrivyOptions opts={opts} setOpts={setOpts} context="cloud" cloud={opts.cloud}/><AiOptions opts={opts} setOpts={setOpts}/></div></div>}
function TrivyOptions({opts,setOpts,context,cloud}){return <div className="nested-options"><label><input type="checkbox" checked={opts.enable_trivy} onChange={e=>setOpts(o=>({...o,enable_trivy:e.target.checked}))}/> Enable Trivy image security scan</label>{opts.enable_trivy&&<><div className="info-box">{context==='local'?'For local scans, Trivy runs inside the DevSecOps Agent backend container built by Docker Compose.':'For AWS EC2 Docker scans, Trivy must exist on the selected EC2 instance. You can enable auto-install below if the instance allows sudo apt installation.'}</div>{context==='cloud'&&cloud?.provider==='aws'&&cloud.services.includes('ec2_docker')&&<label><input type="checkbox" checked={cloud.aws.install_trivy_on_ec2} onChange={e=>setOpts(o=>({...o,cloud:{...o.cloud,aws:{...o.cloud.aws,install_trivy_on_ec2:e.target.checked}}}))}/> Install Trivy on selected EC2 instances if missing</label>}<div className="form-grid"><label>Trivy scanners<input value={opts.trivy_scanners} onChange={e=>setOpts(o=>({...o,trivy_scanners:e.target.value}))}/></label><label>Severity filter<input value={opts.trivy_severity} onChange={e=>setOpts(o=>({...o,trivy_severity:e.target.value}))}/></label><label>Max images<input type="number" value={opts.trivy_max_images} onChange={e=>setOpts(o=>({...o,trivy_max_images:Number(e.target.value)}))}/></label></div></>}</div>}
function AiOptions({opts,setOpts}){function updateAi(p){setOpts(o=>({...o,ai:{...o.ai,...p}}))}return <div className="nested-options"><label><input type="checkbox" checked={opts.ai.enabled} onChange={e=>updateAi({enabled:e.target.checked})}/> Enable optional AI analysis</label>{opts.ai.enabled&&<><div className="form-grid"><label>AI API key optional<input type="password" value={opts.ai.api_key} onChange={e=>updateAi({api_key:e.target.value})} placeholder="Use frontend key for this scan only"/></label><label>Model name<input value={opts.ai.model} onChange={e=>updateAi({model:e.target.value})} placeholder="gpt-4o-mini or compatible model"/></label><label>Base URL optional<input value={opts.ai.base_url} onChange={e=>updateAi({base_url:e.target.value})} placeholder="https://api.openai.com/v1"/></label></div><div className="warning">The AI key is used for this inspection request only and is stored in history as ***provided***.</div></>}</div>}
function AwsForm({cloud,awsRegions,regionsLoading,regionsError,loadAwsRegionList,toggleAwsRegion,selectAllAwsRegions,clearAwsRegions,toggleService,setRegionText,setCred,ec2Instances,ec2Loading,ec2Error,ec2Info,loadEc2InstanceList,toggleEc2Instance}){const selected=cloud.aws.ec2_instance_ids||[];return <div><h3>AWS credentials</h3><div className="form-grid"><label>Access key ID<input value={cloud.aws.access_key_id} onChange={e=>setCred('aws','access_key_id',e.target.value)} placeholder="AKIA..."/></label><label>Secret access key<input type="password" value={cloud.aws.secret_access_key} onChange={e=>setCred('aws','secret_access_key',e.target.value)} placeholder="AWS secret"/></label><label>Session token optional<input type="password" value={cloud.aws.session_token||''} onChange={e=>setCred('aws','session_token',e.target.value)} placeholder="STS session token"/></label><label>Default region <span className="field-hint">used for AWS credential validation; selected regions below are scan targets</span><input value={cloud.aws.region} onChange={e=>setCred('aws','region',e.target.value)} placeholder="us-east-1"/></label></div><div className="aws-region-loader"><div><h3>AWS regions</h3><p className="muted">Load enabled AWS regions, then select one or more regions to scan.</p></div><button type="button" className="secondary-btn" onClick={loadAwsRegionList} disabled={regionsLoading}>{regionsLoading?'Loading regions...':'Load AWS regions'}</button></div>{regionsError&&<div className="error">{regionsError}</div>}<div className="region-actions"><button type="button" className="text-btn" onClick={selectAllAwsRegions}>Select all</button><button type="button" className="text-btn" onClick={clearAwsRegions}>Clear</button></div><div className="region-grid">{awsRegions.map(region=><label key={region} className={`region-chip ${cloud.regions.includes(region)?'selected':''}`}><input type="checkbox" checked={cloud.regions.includes(region)} onChange={()=>toggleAwsRegion(region)}/>{region}</label>)}</div><label>Manual regions, comma separated<input value={(cloud.regions||[]).join(',')} onChange={e=>setRegionText(e.target.value)} placeholder="us-east-1,us-west-2"/></label><h3>AWS scan items</h3><div className="service-grid"><ServiceBox label="AWS EC2 Docker via SSM" checked={cloud.services.includes('ec2_docker')} onChange={()=>toggleService('ec2_docker')}/><ServiceBox label="ECS Containers & Services" checked={cloud.services.includes('ecs')} onChange={()=>toggleService('ecs')}/><ServiceBox label="ECR Images & Scan Findings" checked={cloud.services.includes('ecr')} onChange={()=>toggleService('ecr')}/><ServiceBox label="EC2 Security Groups" checked={cloud.services.includes('security_groups')} onChange={()=>toggleService('security_groups')}/><ServiceBox label="S3 Public Access" checked={cloud.services.includes('s3')} onChange={()=>toggleService('s3')}/><ServiceBox label="IAM Summary" checked={cloud.services.includes('iam')} onChange={()=>toggleService('iam')}/></div>{cloud.services.includes('ec2_docker')&&<div className="nested-options"><div className="section-title"><div><h3>EC2 Docker targets</h3><p className="muted">Load EC2 instances from selected regions. Only SSM-managed instances can be scanned without SSH.</p></div><button type="button" className="secondary-btn" onClick={loadEc2InstanceList} disabled={ec2Loading}>{ec2Loading?'Loading instances...':'Load EC2 Instances'}</button></div>{ec2Error&&<div className="error">{ec2Error}</div>}{ec2Info&&<div className="info">{ec2Info}</div>}<div className="instance-table">{ec2Instances.length===0?<p className="muted">No EC2 instances loaded yet.</p>:ec2Instances.map(inst=>{const key=`${inst.region}:${inst.instance_id}`;return <label key={key} className={`instance-card ${selected.includes(key)?'selected':''} ${!inst.ssm_managed?'disabled':''}`}><input type="checkbox" disabled={!inst.ssm_managed} checked={selected.includes(key)} onChange={()=>toggleEc2Instance(inst)}/><b>{inst.name||inst.instance_id}</b><small>{inst.region} · {inst.instance_id} · {inst.state}</small><span>{inst.ssm_managed?`SSM ${inst.ssm_ping_status||'managed'}`:'Not SSM managed'}</span><small>{inst.public_ip||inst.private_ip||'No IP shown'}</small></label>})}</div></div>}<div className="warning">For plain Docker containers inside EC2, select AWS EC2 Docker via SSM. ECS/ECR scans will not find normal Docker containers running directly on EC2.</div></div>}
function GcpForm({cloud,toggleService,setCred}){return <div><h3>GCP credentials</h3><div className="form-grid"><label>Project ID<input value={cloud.gcp.project_id} onChange={e=>setCred('gcp','project_id',e.target.value)} placeholder="my-gcp-project"/></label></div><label>Service account JSON<textarea value={cloud.gcp.service_account_json} onChange={e=>setCred('gcp','service_account_json',e.target.value)} placeholder='{"type":"service_account", ...}' rows="7"/></label><h3>GCP services</h3><div className="service-grid"><ServiceBox label="Compute Firewall" checked={cloud.services.includes('firewall')} onChange={()=>toggleService('firewall')}/><ServiceBox label="Cloud Storage IAM" checked={cloud.services.includes('storage')} onChange={()=>toggleService('storage')}/></div></div>}
function AzureForm({cloud,toggleService,setCred}){return <div><h3>Azure service principal</h3><div className="form-grid"><label>Tenant ID<input value={cloud.azure.tenant_id} onChange={e=>setCred('azure','tenant_id',e.target.value)} /></label><label>Client ID<input value={cloud.azure.client_id} onChange={e=>setCred('azure','client_id',e.target.value)} /></label><label>Client secret<input type="password" value={cloud.azure.client_secret} onChange={e=>setCred('azure','client_secret',e.target.value)} /></label><label>Subscription ID<input value={cloud.azure.subscription_id} onChange={e=>setCred('azure','subscription_id',e.target.value)} /></label></div><h3>Azure services</h3><div className="service-grid"><ServiceBox label="Network Security Groups" checked={cloud.services.includes('nsg')} onChange={()=>toggleService('nsg')}/><ServiceBox label="Storage Accounts" checked={cloud.services.includes('storage')} onChange={()=>toggleService('storage')}/></div></div>}
function CloudCard({provider,name,image,subtitle,selected,onClick}){ return <button type="button" className={`cloud-card ${selected?'selected':''}`} onClick={onClick} aria-pressed={selected}><span className="cloud-check">✓</span><img src={image} alt={`${name} logo`}/><strong>{name}</strong><small>{subtitle}</small></button> }
function ServiceBox({checked,onChange,label}){ return <label className="service-box"><input type="checkbox" checked={checked} onChange={onChange}/>{label}</label> }
function Card({title,value}){ return <div className="card"><span>{title}</span><strong>{value}</strong></div> }
function ContainerExplorer({containers,selectedContainerId,diagnostics,diagnosticsLoading,diagnosticsError,onSelect,reportId}){containers=asArray(containers); const running=containers.filter(c=>c.status==='running').length; const stopped=containers.filter(c=>c.status!=='running').length; return <div className="panel"><div className="section-title"><div><h2>Local Container Command Center</h2><p className="muted">Select a running or stopped local container to view logs, healthcheck output, exit code, and runtime errors.</p></div>{reportId&&<a className="secondary-btn" href={`#/report/${reportId}`}>Open Full Report</a>}</div><div className="mini-stats"><span>{containers.length} total</span><span>{running} running</span><span>{stopped} stopped</span></div><div className="container-table"><div className="container-row header"><span>Select</span><span>Container</span><span>Image</span><span>Status</span><span>Health</span><span>Exit</span><span>CPU</span></div>{containers.map(c=><div className="container-row" key={c.full_id}><span><input type="checkbox" checked={selectedContainerId===c.full_id} onChange={e=>onSelect(e.target.checked ? c.full_id : '')}/></span><span><b>{c.name}</b><small>{c.id}</small></span><span>{c.image}</span><span><StatusBadge status={c.status}/></span><span>{c.health || 'not configured'}</span><span>{c.exit_code ?? '-'}</span><span>{c.stats?.cpu_percent ?? 0}%</span></div>)}</div>{diagnosticsLoading&&<div className="progress"><div className="progress-item">Loading container diagnostics...</div></div>}{diagnosticsError&&<div className="error">{diagnosticsError}</div>}{diagnostics&&<ContainerDiagnostics diagnostics={diagnostics}/>}</div>}
function CloudEc2DockerExplorer({containers,instances,reportId,aws,logTail}){
 containers=asArray(containers);
 instances=asArray(instances);
 const [selected,setSelected]=useState(null);
 const [remoteDiagnostics,setRemoteDiagnostics]=useState(null);
 const [loading,setLoading]=useState(false);
 const [error,setError]=useState('');
 async function selectRemoteContainer(container,checked){
   if(!checked){ setSelected(null); setRemoteDiagnostics(null); setError(''); return; }
   setSelected(container); setRemoteDiagnostics(null); setError('');
   if(!aws?.access_key_id || !aws?.secret_access_key){
     setError('Live EC2 logs need the AWS credentials still present in this dashboard session. Re-enter credentials or run the scan again, then select the container.');
     setRemoteDiagnostics(container);
     return;
   }
   setLoading(true);
   try{
     const body={
       access_key_id:aws.access_key_id,
       secret_access_key:aws.secret_access_key,
       session_token:aws.session_token || '',
       region:container.region,
       instance_id:container.instance_id,
       container_id:container.full_id || container.id || container.name,
       tail:Math.max(10, Math.min(Number(logTail || 250), 1000))
     };
     const data=await api('/api/cloud/aws/ec2/docker/diagnostics',{method:'POST',body:JSON.stringify(body)});
     setRemoteDiagnostics(data);
   }catch(e){
     const msg = e.message || 'Could not load live EC2 Docker diagnostics. Showing scan-time data instead.';
     const looksLikeRawJson = msg.trim().startsWith('{') || msg.trim().startsWith('[');
     setError(looksLikeRawJson
       ? 'Live diagnostics returned an unexpected raw Docker payload. Showing scan-time data instead. Rebuild with the latest backend fix and try again.'
       : msg);
     setRemoteDiagnostics(container);
   }finally{ setLoading(false); }
 }
 return <div className="panel"><div className="section-title"><div><h2>AWS EC2 Docker Command Center</h2><p className="muted">Remote Docker results collected through AWS Systems Manager. Selecting a container fetches live <b>docker inspect</b> and <b>docker logs</b> from the EC2 instance.</p></div>{reportId&&<a className="secondary-btn" href={`#/report/${reportId}`}>Open Full Report</a>}</div><div className="mini-stats"><span>{instances.length} EC2 instance(s)</span><span>{containers.length} container(s)</span></div><div className="container-table"><div className="container-row header"><span>Select</span><span>EC2 / Container</span><span>Image</span><span>Status</span><span>Health</span><span>Exit</span><span>CPU</span></div>{containers.map((c,i)=><div className="container-row" key={`${c.region}-${c.instance_id}-${c.full_id}-${i}`}><span><input type="checkbox" checked={selected===c} onChange={e=>selectRemoteContainer(c,e.target.checked)}/></span><span><b>{c.name}</b><small>{c.region} · {c.instance_id}</small></span><span>{c.image}</span><span><StatusBadge status={c.status}/></span><span>{c.health || 'not configured'}</span><span>{c.exit_code ?? '-'}</span><span>{c.stats?.cpu_percent || '-'}</span></div>)}</div>{loading&&<div className="progress live-diagnostics-loading"><div className="progress-item live-fetch-line"><span>Fetching live EC2 Docker logs and diagnostics via SSM</span><span className="animated-dots" aria-label="loading"><i></i><i></i><i></i></span></div><div className="live-fetch-subtext">Running remote docker logs and inspect commands on the selected EC2 instance. This can take a few seconds.</div></div>}{error&&<div className="error">{error}</div>}{(remoteDiagnostics||selected)&&<ContainerDiagnostics diagnostics={remoteDiagnostics||selected}/>}</div>}
function StatusBadge({status}){ const text=String(status||'unknown').toLowerCase(); const cls=text==='running'?'low':text==='exited'?'medium':'high'; return <span className={`badge ${cls}`}>{text}</span> }
function shortContainerId(id){ return String(id||'').slice(0,12) || '-'; }
function formatDateTime(value){
  if(!value || value.startsWith?.('0001-')) return '-';
  const d=new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}
function yesNo(value){ return value ? 'Yes' : 'No'; }
function asObject(value){ return value && typeof value === 'object' && !Array.isArray(value) ? value : {}; }
function asArray(value){
  if(Array.isArray(value)) return value;
  if(value == null || value === '') return [];
  if(typeof value === 'object') return Object.values(value);
  return [];
}
function toSafeText(value){
  if(value == null) return '';
  if(typeof value === 'string') return value;
  try { return JSON.stringify(value,null,2); } catch { return String(value); }
}
function normalizeHealth(value){
  if(!value) return {status:'not configured', log:[]};
  if(typeof value === 'string') return {status:value, log:[]};
  if(typeof value === 'object') return {...value, status:value.status || value.Status || 'not configured', log:asArray(value.log || value.Log)};
  return {status:'not configured', log:[]};
}
function inferLikelyCause(diagnostics,state){
  const logs=String(diagnostics.logs_tail||'');
  const image=String(diagnostics.image||diagnostics.inspect?.Config?.Image||'').toLowerCase();
  if(/password option is not specified|MYSQL_ROOT_PASSWORD|MYSQL_ALLOW_EMPTY_PASSWORD|MYSQL_RANDOM_ROOT_PASSWORD/i.test(logs)){
    return 'MySQL exited because the database is uninitialized and no root password option was provided. Set MYSQL_ROOT_PASSWORD, MYSQL_ALLOW_EMPTY_PASSWORD, or MYSQL_RANDOM_ROOT_PASSWORD.';
  }
  if(/permission denied/i.test(logs)) return 'The container logs include a permission denied error. Check file ownership, mounted volumes, and the user running inside the container.';
  if(/address already in use|port is already allocated/i.test(logs)) return 'The container likely failed because a required port is already in use on the host.';
  if(/cannot connect|connection refused/i.test(logs)) return 'The container logs show a connection failure. Check dependent services, network names, ports, and environment variables.';
  if(state?.oom_killed || state?.OOMKilled) return 'The container was OOM killed. Increase memory or reduce the application memory usage.';
  if((state?.exit_code ?? state?.ExitCode) && String(state.status||state.Status||diagnostics.status).toLowerCase()!=='running') return 'The container exited with a non-zero status. Review the logs first, then inspect environment variables, volumes, and startup command.';
  if(image.includes('mysql') && String(diagnostics.status||state?.status||'').toLowerCase()!=='running') return 'This is a stopped MySQL container. Review logs and required MySQL environment variables first.';
  return diagnostics.detected_error || 'No specific root cause detected automatically. Review logs, runtime state, mounts, and ports.';
}
function normalizePorts(ports){
  if(!ports || Array.isArray(ports) && ports.length===0) return [];
  if(Array.isArray(ports)) return ports.map((p,i)=>({container:p.container_port||p.PrivatePort||p.port||`port-${i}`, host:p.host_port||p.PublicPort||'-', ip:p.host_ip||p.IP||'-', protocol:p.protocol||p.Type||''}));
  return Object.entries(ports).flatMap(([containerPort,bindings])=>{
    if(!bindings) return [{container:containerPort, host:'-', ip:'-', protocol:''}];
    return (Array.isArray(bindings)?bindings:[bindings]).map(b=>({container:containerPort, host:b.HostPort||b.host_port||'-', ip:b.HostIp||b.host_ip||'-', protocol:''}));
  });
}
function ContainerDiagnostics({diagnostics}){
 const safeDiagnostics=asObject(diagnostics);
 const inspect=asObject(safeDiagnostics.inspect);
 const state=asObject(safeDiagnostics.state || inspect.State);
 const health=normalizeHealth(safeDiagnostics.health || state.Health);
 const ports=normalizePorts(safeDiagnostics.ports || inspect?.NetworkSettings?.Ports || {});
 const mounts=asArray(safeDiagnostics.mounts || inspect?.Mounts);
 const fullId=safeDiagnostics.full_id || inspect?.Id || safeDiagnostics.id;
 const name=String(safeDiagnostics.name || inspect?.Name || 'container').replace(/^\//,'');
 const image=safeDiagnostics.image || inspect?.Config?.Image || '-';
 const status=(state.status || state.Status || safeDiagnostics.status || 'unknown');
 const exitCode=safeDiagnostics.exit_code ?? state.exit_code ?? state.ExitCode ?? '-';
 const likelyCause=inferLikelyCause(safeDiagnostics,state);
 const logsTail=toSafeText(safeDiagnostics.logs_tail || safeDiagnostics.logs || '');
 const rawInspect=Object.keys(inspect).length ? inspect : {
   Id: fullId,
   Name: name,
   Config: {Image: image},
   State: state,
   RestartCount: safeDiagnostics.restart_count ?? 0,
   NetworkSettings: {Ports: safeDiagnostics.ports || {}},
   Mounts: mounts
 };
 return <div className="diagnostics structured-diagnostics">
   <div className="diagnostics-header">
     <div>
       <h3>{name} diagnostics</h3>
       <p className="muted">Readable Docker inspect summary, live logs, runtime details, ports, and mounts.</p>
     </div>
     <span className="pill-id">{shortContainerId(fullId)}</span>
   </div>

   <div className="failure-summary">
     <div>
       <span className="section-kicker">Quick failure summary</span>
       <h4>{status === 'running' ? 'Container is running' : `Container is ${status}`}</h4>
       <p>{likelyCause}</p>
     </div>
     <div className="summary-facts">
       <span><b>Image</b>{image}</span>
       <span><b>Exit code</b>{exitCode}</span>
       <span><b>Restart count</b>{safeDiagnostics.restart_count ?? inspect?.RestartCount ?? 0}</span>
     </div>
   </div>

   <h4>Container logs</h4>
   <CodeBlock>{logsTail || 'No logs returned from this container.'}</CodeBlock>

   <div className="diagnostic-section">
     <h4>Runtime details</h4>
     <div className="detail-cards">
       <Card title="Status" value={status}/>
       <Card title="Health" value={health.status || 'not configured'}/>
       <Card title="Exit Code" value={exitCode}/>
       <Card title="OOM Killed" value={yesNo(state.oom_killed ?? state.OOMKilled)}/>
       <Card title="Dead" value={yesNo(state.dead ?? state.Dead)}/>
       <Card title="Restarts" value={safeDiagnostics.restart_count ?? inspect?.RestartCount ?? 0}/>
     </div>
     <div className="runtime-times">
       <span><b>Started</b>{formatDateTime(state.started_at || state.StartedAt)}</span>
       <span><b>Finished</b>{formatDateTime(state.finished_at || state.FinishedAt)}</span>
     </div>
     {safeDiagnostics.detected_error&&<div className="error"><b>Error detected:</b> {safeDiagnostics.detected_error}</div>}
   </div>

   <div className="details-grid">
     <div>
       <h4>Healthcheck</h4>
       {asArray(health.log).length===0?<p className="muted">No container healthcheck log is configured.</p>:asArray(health.log).map((h,i)=>{const entry=asObject(h); return <div className="health-entry" key={i}><b>Attempt {i+1}</b><span>Exit: {entry.exit_code ?? entry.ExitCode ?? '-'}</span><CodeBlock>{entry.output || entry.Output || 'No output'}</CodeBlock></div>})}
     </div>
     <div>
       <h4>Runtime state JSON</h4>
       <CodeBlock>{JSON.stringify(state,null,2)}</CodeBlock>
     </div>
   </div>

   <div className="diagnostic-section">
     <h4>Network & ports</h4>
     {ports.length===0?<p className="muted">No exposed ports found.</p>:<div className="simple-table"><div className="simple-row header"><span>Container port</span><span>Host port</span><span>Host IP</span></div>{ports.map((p,i)=><div className="simple-row" key={i}><span>{p.container}</span><span>{p.host}</span><span>{p.ip}</span></div>)}</div>}
   </div>

   <div className="diagnostic-section">
     <h4>Mounts / volumes</h4>
     {mounts.length===0?<p className="muted">No mounts or volumes found.</p>:<div className="simple-table mounts-table"><div className="simple-row header"><span>Type</span><span>Destination</span><span>RW</span><span>Source</span></div>{mounts.map((m,i)=><div className="simple-row" key={i}><span>{m.Type||m.type||'-'}</span><span>{m.Destination||m.destination||'-'}</span><span>{yesNo(m.RW ?? m.rw)}</span><span>{m.Source||m.source||m.Name||m.name||'-'}</span></div>)}</div>}
   </div>

   <details className="advanced-json">
     <summary>Advanced Docker inspect JSON</summary>
     <CodeBlock>{JSON.stringify(rawInspect,null,2)}</CodeBlock>
   </details>
 </div>
}
