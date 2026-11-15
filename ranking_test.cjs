const {rankResults}=require('./web/ranking.js');
const assert=require('node:assert/strict');
const row=(server,status,ms,error='')=>({server,status,ms,error,transport:'doh3',domain:'example.com',type:'A'});
assert.deepEqual(rankResults([row('fast-error','error',1,'timeout'),row('slow','passed',500),row('fast','passed',100),row('fake','suspicious',1)]).map(x=>x.key),['fast / DOH3','slow / DOH3','fake / DOH3','fast-error / DOH3']);
const ranked=rankResults([row('a','passed',100),row('a','error',5000,'timeout'),row('b','passed',200),row('b','passed',200),row('b','error',5000,'timeout')]);assert.equal(ranked[0].key,'b / DOH3');assert.equal(ranked[0].p95,200);assert.deepEqual(rankResults([]),[]);
console.log('Ranking checks passed');
