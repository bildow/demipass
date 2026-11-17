"use strict";
// Endpoint-only framing and acknowledgments; no relay sees plaintext or private keys.
const crypto=require("node:crypto"),{TextDecoder}=require("node:util"),p=require("./crypto");
const MAGIC=Buffer.from("conduit-pad-v1\n"),HEADER=MAGIC.length+4;
const BLOCKS={"1k":1024,"4k":4096,"16k":16384};
function encode(plaintext,padding="none") {
  if(typeof plaintext!=="string")throw Error("plaintext must be string");
  if(padding==="none")return plaintext;
  if(!Object.hasOwn(BLOCKS,padding))throw Error("unknown padding bucket");
  const bytes=Buffer.from(plaintext),n=BLOCKS[padding];
  if(bytes.length>n-HEADER)throw Error("plaintext exceeds selected padding bucket");
  const frame=crypto.randomBytes(n);MAGIC.copy(frame);frame.writeUInt32BE(bytes.length,MAGIC.length);bytes.copy(frame,HEADER);
  try{return frame.toString("base64url");}finally{frame.fill(0);bytes.fill(0);}
}
function decode(plaintext,padding="none") {
  if(padding==="none")return plaintext;
  if(!Object.hasOwn(BLOCKS,padding))throw Error("unknown padding bucket");
  // bytes' second argument requires exact length (b.length !== length), not a cap.
  const frame=p.bytes(plaintext,BLOCKS[padding]);
  try{
    if(!frame.subarray(0,MAGIC.length).equals(MAGIC))throw Error("padding frame mismatch");
    const n=frame.readUInt32BE(MAGIC.length);if(n>frame.length-HEADER)throw Error("padding length invalid");
    return new TextDecoder("utf-8",{fatal:true}).decode(frame.subarray(HEADER,HEADER+n));
  }finally{frame.fill(0);}
}
function receiptBody(envelope,release,recipient,at,padding) {
  if(envelope.header.mode==="direct"&&release!==null)throw Error("direct message cannot claim guardian release");
  if(!Number.isSafeInteger(at)||at<0)throw Error("invalid acknowledgment time");
  if(padding!=="none"&&!Object.hasOwn(BLOCKS,padding))throw Error("unknown padding bucket");
  return {format:"conduit-decryption-ack-v1",event:"decrypted",envelope_hash:p.hash(envelope),
    capsule_hash:envelope.capsule_hash,recipient_key:p.keyId(recipient),
    release_hash:release?p.hash({grant_hash:release.grant_hash,responses:release.responses}):null,
    padding,at};
}
function verifyAcknowledgment({ack,envelope,release=null,sender,recipient,padding="none"}) {
  p.validateEnvelope(envelope,sender,recipient);p.fields(ack,["body","signature"]);
  const expected=receiptBody(envelope,release,recipient,ack.body && ack.body.at,padding);
  if(p.canonical(ack.body)!==p.canonical(expected)||!p.verify(ack.body,ack.signature,recipient.sign))
    throw Error("decryption acknowledgment binding invalid");
  return {event:"decrypted",envelope_hash:expected.envelope_hash,at:expected.at,
    assertion:"recipient-signed endpoint assertion; not proof a human/model read it"};
}
async function openAcknowledged({envelope,capsule,sender,recipient,policy=null,release=null,padding="none"}) {
  // Never sign an acknowledgment on missing keys, invalid crypto or framing failure.
  const plaintext=decode(await p.open({envelope,capsule,sender,recipient,policy,release}),padding);
  // Sample the endpoint clock after successful decrypt/decode. Request fields
  // (including an extra `now`) cannot choose the time signed by this endpoint.
  const body=receiptBody(envelope,release,recipient.publicKey,Date.now(),padding);
  return {plaintext,ack:{body,signature:p.sign(body,recipient.signPrivate)}};
}
module.exports={encode,decode,openAcknowledged,verifyAcknowledgment,BLOCKS};
