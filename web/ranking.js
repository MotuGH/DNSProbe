'use strict';
function rankResults(rows){
 const groups=new Map();
 for(const x of rows){const key=x.server+' / '+x.transport.toUpperCase();if(!groups.has(key))groups.set(key,[]);groups.get(key).push(x)}
 return [...groups].map(([key,a])=>{
  let errors=0,suspicious=0,longest=0;const series=new Map(),latencies=[];
  for(const x of a){const failed=!!x.error||x.status==='error';if(failed)errors++;else if(x.status==='suspicious')suspicious++;else if(Number.isFinite(x.ms))latencies.push(x.ms);
   const k=x.domain+'/'+x.type,n=failed?(series.get(k)||0)+1:0;series.set(k,n);longest=Math.max(longest,n)}
  latencies.sort((a,b)=>a-b);
  return {key,count:a.length,received:a.filter(x=>!x.error).length,errors,suspicious,badRate:(errors+suspicious)/a.length,p95:latencies.length?latencies[Math.ceil(latencies.length*.95)-1]:Infinity,longest};
 }).sort((a,b)=>a.badRate-b.badRate||(a.p95===b.p95?0:a.p95-b.p95)||b.count-a.count||a.key.localeCompare(b.key));
}
if(typeof module!=='undefined')module.exports={rankResults};
