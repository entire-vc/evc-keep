// RFC 9180 base mode: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
// This module uses browser primitives only and makes no network requests.
const utf8 = new TextEncoder();
const version = utf8.encode('HPKE-v1');
const kemSuite = new Uint8Array([75,69,77,0,32]);
const hpkeSuite = new Uint8Array([72,80,75,69,0,32,0,1,0,2]);
const empty = new Uint8Array();
// RFC 9180 section 5.2: Seal fails if IncrementSeq would overflow Nn bytes.
// With a 12-byte nonce, sequence 2^96-2 succeeds; 2^96-1 must fail.
const sequenceLimit = (1n << 96n) - 1n;
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n,p)=>n+p.length,0));
  let offset=0;
  for(const part of parts) { out.set(part,offset); offset+=part.length; }
  return out;
};

async function hmac(key,data) {
  const imported=await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-256'},false,['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC',imported,data));
}
async function extract(salt,label,ikm,suite) {
  return hmac(salt.length?salt:new Uint8Array(32),concat(version,suite,utf8.encode(label),ikm));
}
async function expand(prk,label,info,length,suite) {
  if(length<1 || length>255*32) throw new Error('invalid HPKE expansion');
  const context=concat(new Uint8Array([length>>8,length&255]),version,suite,utf8.encode(label),info);
  const output=new Uint8Array(length);
  let previous=empty,offset=0;
  for(let block=1;offset<length;block++) {
    const next=await hmac(prk,concat(previous,context,new Uint8Array([block])));
    previous.fill(0); previous=next;
    const n=Math.min(next.length,length-offset);
    output.set(next.subarray(0,n),offset); offset+=n;
  }
  previous.fill(0);
  return output;
}

// Every sender owns a fresh, non-extractable private key.
export async function setupSender(recipient,info) {
  if(!(recipient instanceof Uint8Array) || recipient.length!==32 || !(info instanceof Uint8Array)) throw new Error('invalid HPKE input');
  const pair=await crypto.subtle.generateKey('X25519',false,['deriveBits']);
  const ephemeral=pair.privateKey;
  const enc=new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey));
  const remote=await crypto.subtle.importKey('raw',recipient,'X25519',false,[]);
  const dh=new Uint8Array(await crypto.subtle.deriveBits({name:'X25519',public:remote},ephemeral,256));
  let eae,shared,secret,key,baseNonce;
  try {
    if(dh.every(byte=>byte===0)) throw new Error('invalid HPKE shared secret');
    eae=await extract(empty,'eae_prk',dh,kemSuite);
    shared=await expand(eae,'shared_secret',concat(enc,recipient),32,kemSuite);
    const pskHash=await extract(empty,'psk_id_hash',empty,hpkeSuite);
    const infoHash=await extract(empty,'info_hash',info,hpkeSuite);
    const context=concat(new Uint8Array([0]),pskHash,infoHash);
    secret=await extract(shared,'secret',empty,hpkeSuite);
    key=await expand(secret,'key',context,32,hpkeSuite);
    baseNonce=await expand(secret,'base_nonce',context,12,hpkeSuite);
    const aes=await crypto.subtle.importKey('raw',key,'AES-GCM',false,['encrypt']);
    let sequence=0n;
    return {
      enc,
      async seal(plaintext,aad=empty) {
        if(sequence>=sequenceLimit) throw new Error('HPKE message limit reached');
        const nonce=baseNonce.slice();
        let counter=sequence++;
        for(let i=nonce.length-1;i>=0;i--) { nonce[i]^=Number(counter&255n); counter>>=8n; }
        return new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:aad,tagLength:128},aes,plaintext));
      }
    };
  } finally {
    dh.fill(0); eae?.fill(0); shared?.fill(0); secret?.fill(0); key?.fill(0);
  }
}

export function intakeInfo(requestID) {
  if(typeof requestID!=='string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(requestID)) throw new Error('invalid intake request id');
  return utf8.encode('keep/intake/v1\x00'+requestID);
}
