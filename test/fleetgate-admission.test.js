'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),http=require('http');
const {fleetgateAdmission}=require('../fleetgate-admission');
test('readiness refuses legacy 404, malformed evidence, redirects and wrong authority; never sends session',async()=>{
 let code=200,body; const good={ok:true,wallet:'wallet',admission:{ok:true,protocol:1,release_authorized:false,charter_sha256:'a'.repeat(64),lanes:[{name:'intake',repos:['repo'],paths:['docs/**'],add_only:[],deny:[]}]}};
 const server=http.createServer((req,res)=>{assert.equal(req.headers.authorization,'Bearer service-token');assert.equal(req.url,'/v1/onboard');assert.equal(req.method,'POST');res.writeHead(code,{'Content-Type':'application/json',Location:'http://example.com'});res.end(JSON.stringify(body));});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const run=()=>fleetgateAdmission({endpoint:`http://127.0.0.1:${server.address().port}`,token:'service-token',wallet:'wallet'});
 try{
  for(const b of [null,[],{}, {...good,wallet:'other'}, {...good,admission:{...good.admission,release_authorized:true}}, {...good,admission:{...good.admission,lanes:[]}}, {...good,admission:{...good.admission,charter_sha256:'no'}}]){body=b;assert.equal((await run()).ok,false);}
  body=good;for(const c of [302,403,404,500]){code=c;assert.equal((await run()).ok,false);}
  code=200;assert.equal((await run()).ok,true);
  assert.equal((await fleetgateAdmission({endpoint:'http://public.example',token:'service-token',wallet:'wallet'})).ok,false);
 }finally{server.close();}
});
