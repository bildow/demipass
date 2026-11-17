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
test("failed authentication or wrong padding never creates acknowledgment; signing cannot imply reading",async t=>{
 const f=await fixture(t),packet=await p.seal({sender:f.a.key(),recipient:f.recipient,plaintext:"ordinary unpadded text"});
 await assert.rejects(f.b.openAcknowledged({...packet,capsule:undefined,sender:f.sender}));
 await assert.rejects(f.b.openAcknowledged({...packet,sender:f.sender,padding:"1k"}));
 assert.equal(fs.existsSync(path.join(f.root,"b/acknowledgments")),false);
 const got=await f.b.openAcknowledged({...packet,sender:f.sender});
 assert.match(l.verifyAcknowledgment({...packet,sender:f.sender,recipient:f.recipient,ack:got.ack}).assertion,/not proof/);
});

test("actual MCP open returns opt-in acknowledgment and decodes padding without service access",async t=>{
 const f=await fixture(t),out=await f.a.prepare({recipient:f.recipient,plaintext:"MCP private",padding:"1k",defer_capsule:false});
 const packet=JSON.parse(f.a.transport(out.id).body),config=path.join(f.root,"conduit.json");
 fs.writeFileSync(config,JSON.stringify({name:"recipient"}),{mode:0o600});
 const request={jsonrpc:"2.0",id:1,method:"tools/call",params:{name:"conduit_sealed_open",
  arguments:{...packet,sender:f.sender,padding:"1k",acknowledge:true}}};
 const result=require("node:child_process").spawnSync(process.execPath,[path.resolve(__dirname,"../mcp-server.js")],
  {input:JSON.stringify(request)+"\n",encoding:"utf8",timeout:10000,env:{PATH:process.env.PATH,HOME:f.root,
   CONDUIT_CONFIG:config,DEMIPASS_SEALED_ENABLE:"1",DEMIPASS_SEALED_DIRECTORY:path.join(f.root,"b")}});
 assert.equal(result.status,0,result.stderr);const reply=JSON.parse(result.stdout.trim());
 assert.equal(reply.result.isError,undefined);const value=JSON.parse(reply.result.content[0].text);
 assert.equal(value.plaintext,"MCP private");assert.equal(value.ack.body.event,"decrypted");
});
