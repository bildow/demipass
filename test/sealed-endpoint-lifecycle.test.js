"use strict";
const test=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),os=require("node:os"),path=require("node:path"),
 p=require("../sealed/crypto"),l=require("../sealed/endpoint-lifecycle"),{Client}=require("../sealed/client");
async function fixture(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),"sealed-endpoint-"));
 t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const a=new Client({directory:path.join(root,"a"),mailbox:"sender"}),b=new Client({directory:path.join(root,"b"),mailbox:"recipient"});
 const sender=(await a.initialize()).public_key,recipient=(await b.initialize()).public_key;return {root,a,b,sender,recipient};}
test("padding buckets roundtrip unicode, hide within-bucket length, and refuse overflow/mismatched framing",async t=>{
 const f=await fixture(t);let length;
 for(const plaintext of ["a","a considerably longer message 🐕"]){
  const out=await f.a.prepare({recipient:f.recipient,plaintext,padding:"1k",defer_capsule:false});
  const packet=JSON.parse(f.a.transport(out.id).body);assert.equal(out.padding,"1k");
  if(length)assert.equal(packet.envelope.payload.ct.length,length);length=packet.envelope.payload.ct.length;
  assert.equal(await f.b.open({...packet,sender:f.sender,padding:"1k"}),plaintext);
  await assert.rejects(f.b.open({...packet,sender:f.sender,padding:"4k"}));
 }
 for(const padding of ["4k","16k"])assert.equal(l.decode(l.encode("text",padding),padding),"text");
 assert.throws(()=>l.encode("x".repeat(1024),"1k"));assert.throws(()=>l.encode("x","other"));
 const invalid=Buffer.from(l.encode("x","1k"),"base64url");invalid.writeUInt32BE(2000,14);
 assert.throws(()=>l.decode(invalid.toString("base64url"),"1k"));
});
test("durable acknowledgment follows actual decrypt, is bound and replayed, contains no plaintext",async t=>{
 const f=await fixture(t),out=await f.a.prepare({recipient:f.recipient,plaintext:"NEVER LOG THIS",padding:"1k",defer_capsule:false}),
 packet=JSON.parse(f.a.transport(out.id).body),args={...packet,sender:f.sender,padding:"1k"};
 const got=await f.b.openAcknowledged(args);assert.equal(got.plaintext,"NEVER LOG THIS");
 assert.equal(l.verifyAcknowledgment({...args,ack:got.ack,recipient:f.recipient}).event,"decrypted");
 assert.deepEqual((await f.b.openAcknowledged(args)).ack,got.ack);
 const raw=fs.readFileSync(path.join(f.root,"b/acknowledgments",p.hash(packet.envelope)+".json"),"utf8");
 assert(!raw.includes("NEVER LOG THIS"));assert(!raw.includes("signPrivate"));
 const bad=structuredClone(got.ack);bad.body.event="read";
 assert.throws(()=>l.verifyAcknowledgment({...args,ack:bad,recipient:f.recipient}));
 const wrong=await p.identity("recipient");assert.throws(()=>l.verifyAcknowledgment({...args,ack:got.ack,recipient:wrong.publicKey}));
 const other=await p.seal({sender:f.a.key(),recipient:f.recipient,plaintext:"other"});
 assert.throws(()=>l.verifyAcknowledgment({...args,envelope:other.envelope,ack:got.ack,recipient:f.recipient}));
});
test("padding requires exact bucket size, including for encrypted short frames; capacity includes the 19-byte header",async t=>{
 const f=await fixture(t),magic=Buffer.from("conduit-pad-v1\n"),header=magic.length+4;
 assert.equal(header,19);
 for(const [padding,size] of Object.entries(l.BLOCKS)){
  const capacity=size-header,full=l.encode("x".repeat(capacity),padding);
  assert.equal(Buffer.from(full,"base64url").length,size);
  assert.equal(l.decode(full,padding),"x".repeat(capacity));
  assert.throws(()=>l.encode("x".repeat(capacity+1),padding),/exceeds/);
  for(const length of [header+1,size-1,size+1]){
   const frame=Buffer.alloc(length);magic.copy(frame);frame.writeUInt32BE(1,magic.length);frame[header]=120;
   const plaintext=frame.toString("base64url");
   assert.throws(()=>l.decode(plaintext,padding),/invalid encoded length/);
   const packet=await p.seal({sender:f.a.key(),recipient:f.recipient,plaintext});
   await assert.rejects(f.b.openAcknowledged({...packet,sender:f.sender,padding}),/invalid encoded length/);
   assert.equal(fs.existsSync(path.join(f.root,"b/acknowledgments")),false);
  }
 }
});
test("failed authentication or wrong padding never creates acknowledgment; signing cannot imply reading",async t=>{
 const f=await fixture(t),packet=await p.seal({sender:f.a.key(),recipient:f.recipient,plaintext:"ordinary unpadded text"});
 await assert.rejects(f.b.openAcknowledged({...packet,capsule:undefined,sender:f.sender}));
 await assert.rejects(f.b.openAcknowledged({...packet,sender:f.sender,padding:"1k"}));
 assert.equal(fs.existsSync(path.join(f.root,"b/acknowledgments")),false);
 const got=await f.b.openAcknowledged({...packet,sender:f.sender});
 assert.match(l.verifyAcknowledgment({...packet,sender:f.sender,recipient:f.recipient,ack:got.ack}).assertion,/not proof/);
});

test("SDK request time cannot forge a signed timestamp or replace a durable acknowledgment",async t=>{
 const f=await fixture(t);
 for(const now of [0,4102444800000]){
  const packet=await p.seal({sender:f.a.key(),recipient:f.recipient,plaintext:"time control"});
  const args={...packet,sender:f.sender,now};
  const before=Date.now(),got=await f.b.openAcknowledged(args),after=Date.now();
  assert(got.ack.body.at>=before && got.ack.body.at<=after);
  assert.notEqual(got.ack.body.at,now);
  assert.equal(l.verifyAcknowledgment({...args,ack:got.ack,recipient:f.recipient}).at,got.ack.body.at);
  assert.deepEqual((await f.b.openAcknowledged({...args,now:now===0?4102444800000:0})).ack,got.ack);
  const saved=JSON.parse(fs.readFileSync(path.join(f.root,"b/acknowledgments",p.hash(packet.envelope)+".json"),"utf8"));
  assert.deepEqual(saved,got.ack);
 }
});

test("acknowledgment samples endpoint time after asynchronous decrypt, never request time",async t=>{
 const f=await fixture(t),packet=await p.seal({sender:f.a.key(),recipient:f.recipient,plaintext:"clock boundary"});
 const original=p.open;let clock=1000;
 t.mock.method(Date,"now",()=>clock);
 t.mock.method(p,"open",async args=>{const plaintext=await original(args);clock=2000;return plaintext;});
 const got=await l.openAcknowledged({...packet,sender:f.sender,recipient:f.b.key(),now:4102444800000});
 assert.equal(got.ack.body.at,2000);
 assert.equal(l.verifyAcknowledgment({...packet,sender:f.sender,recipient:f.recipient,ack:got.ack}).at,2000);
});

test("actual MCP open returns opt-in acknowledgment and decodes padding without service access",async t=>{
 const f=await fixture(t),out=await f.a.prepare({recipient:f.recipient,plaintext:"MCP private",padding:"1k",defer_capsule:false});
 const packet=JSON.parse(f.a.transport(out.id).body),config=path.join(f.root,"conduit.json");
 fs.writeFileSync(config,JSON.stringify({name:"recipient"}),{mode:0o600});
 const request={jsonrpc:"2.0",id:1,method:"tools/call",params:{name:"conduit_sealed_open",
  arguments:{...packet,sender:f.sender,padding:"1k",acknowledge:true,now:4102444800000}}};
 const before=Date.now();
 const result=require("node:child_process").spawnSync(process.execPath,[path.resolve(__dirname,"../mcp-server.js")],
  {input:JSON.stringify(request)+"\n",encoding:"utf8",timeout:10000,env:{PATH:process.env.PATH,HOME:f.root,
   CONDUIT_CONFIG:config,DEMIPASS_SEALED_ENABLE:"1",DEMIPASS_SEALED_DIRECTORY:path.join(f.root,"b")}});
 assert.equal(result.status,0,result.stderr);const reply=JSON.parse(result.stdout.trim());
 assert.equal(reply.result.isError,undefined);const value=JSON.parse(reply.result.content[0].text);
 assert.equal(value.plaintext,"MCP private");assert.equal(value.ack.body.event,"decrypted");
 assert(value.ack.body.at>=before && value.ack.body.at<=Date.now());
 assert.notEqual(value.ack.body.at,4102444800000);
 assert.equal(l.verifyAcknowledgment({...packet,sender:f.sender,recipient:f.recipient,padding:"1k",ack:value.ack}).at,value.ack.body.at);
});
