const form = document.querySelector('form');
const field = document.querySelector('#secret');
const submit = form.querySelector('button');
const status = document.querySelector('#status');
const from64 = s => {
  const bytes = Uint8Array.from(atob(s), c => c.charCodeAt(0));
  if (to64(bytes) !== s) throw new Error('noncanonical encoding');
  return bytes;
};
const to64 = b => {
  let s = '';
  for (const n of b) s += String.fromCharCode(n);
  return btoa(s);
};
let verified = false;
const visible = node => {
  if (![...node.getClientRects()].some(rect => rect.width > 0 && rect.height > 0)) return false;
  for (let parent = node; parent; parent = parent.parentElement) {
    const style = getComputedStyle(parent);
    if (parent.hidden || style.display === 'none' || style.visibility !== 'visible' || Number(style.opacity) === 0) return false;
  }
  return true;
};
const validateStructureText = node => {
  for (const child of node.childNodes) {
    if (child.nodeType !== Node.ELEMENT_NODE && !(child.nodeType === Node.TEXT_NODE && /^[\t\n\r ]*$/.test(child.textContent))) throw new Error('untrusted metadata');
  }
};
const validateMetadataStructure = nodes => {
  const [name, scope, store, classification, requester, sponsor] = nodes;
  const cards = document.querySelectorAll('section.card');
  const card = cards[0];
  if (cards.length !== 1 || form.parentElement !== card) throw new Error('untrusted metadata');
  validateStructureText(card);
  const [top, heading, list, input, result, state] = card.children;
  if (card.children.length !== 6 || top?.className !== 'card-top' || heading !== name || heading.tagName !== 'H2' || list?.tagName !== 'DL' || input !== form || result?.id !== 'result' || state !== status) throw new Error('untrusted metadata');
  validateStructureText(top);
  validateStructureText(list);
  if (top.children.length !== 2 || top.children[0].tagName !== 'SPAN' || top.children[0].textContent !== 'INPUT REQUEST' || top.children[1] !== classification || classification.tagName !== 'SPAN' || classification.className !== 'badge') throw new Error('untrusted metadata');
  const rows = [['Requested by', requester], ...(sponsor ? [['Sponsor', sponsor]] : []), ['Scope', scope], ['Storage', store]];
  if (list.children.length !== rows.length) throw new Error('untrusted metadata');
  for (let i = 0; i < rows.length; i++) {
    const row = list.children[i];
    validateStructureText(row);
    const [label, value] = rows[i];
    const [dt, dd] = row.children;
    if (row.tagName !== 'DIV' || row.children.length !== 2 || dt?.tagName !== 'DT' || dt.children.length !== 0 || dt.textContent !== label || !visible(dt) || dd !== value || dd.tagName !== 'DD') throw new Error('untrusted metadata');
  }
};
const shownMetadata = () => {
  const names = ['SecretName', 'Scope', 'StoreName', 'Class', 'RequestedBy', 'Sponsor'];
  const nodes = names.map(name => {
    const matches = document.querySelectorAll('#metadata-' + name);
    if (matches.length !== 1 && !(name === 'Sponsor' && matches.length === 0)) throw new Error('untrusted metadata');
    const node = matches[0];
    if (node && (node.children.length !== 0 || !visible(node))) throw new Error('untrusted metadata');
    return node;
  });
  validateMetadataStructure(nodes);
  return nodes.map(node => node?.textContent ?? '');
};
try {
  // The authenticated issuance channel pins this key in the URL fragment.
  // A signer supplied by an untrusted page cannot authorize itself.
  const fragment = new URLSearchParams(location.hash.slice(1));
  if ([...fragment.keys()].some(name => name !== 'request' && name !== 'signing')) throw new Error('untrusted fragment');
  const requests = fragment.getAll('request');
  if (requests.length !== 1 || requests[0] !== form.dataset.request) throw new Error('untrusted request');
  const pins = fragment.getAll('signing');
  const pin = pins[0];
  if (pins.length !== 1 || !/^[A-Za-z0-9_-]{43}$/.test(pin)) throw new Error('untrusted key');
  const signing = from64(pin.replaceAll('-', '+').replaceAll('_', '/') + '=');
  if (signing.length !== 32) throw new Error('untrusted key');
  if (to64(signing) !== form.dataset.signing) throw new Error('untrusted key');
  const publicKey = from64(form.dataset.public);
  const signature = from64(form.dataset.signature);
  if (publicKey.length !== 32 || signature.length !== 64) throw new Error('untrusted key');
  intakeInfo(form.dataset.request);
  const key = await crypto.subtle.importKey('raw', signing, 'Ed25519', false, ['verify']);
  // Sign the text the human sees, never a separate hidden metadata copy.
  const metadata = shownMetadata();
  const fields = [utf8.encode(form.dataset.request), publicKey, ...metadata.map(value => utf8.encode(value))];
  const parts = fields.map(value => {
    const part = new Uint8Array(4 + value.length);
    new DataView(part.buffer).setUint32(0, value.length, false);
    part.set(value, 4);
    return part;
  });
  const domain = utf8.encode('keep/intake-key/v2\x00');
  const message = new Uint8Array(domain.length + parts.reduce((length, part) => length + part.length, 0));
  message.set(domain);
  let offset = domain.length;
  for (const part of parts) { message.set(part, offset); offset += part.length; }
  verified = await crypto.subtle.verify('Ed25519', key, signature, message);
  if (!verified) throw new Error('untrusted key');
  field.disabled = false;
  submit.disabled = false;
  status.textContent = 'Ready for secure input.';
} catch {
  status.textContent = 'This link could not be verified. Ask the requester for a new link.';
  status.dataset.state = 'error';
}
form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!verified || submit.disabled) return;
  submit.disabled = true;
  field.disabled = true;
  const plain = utf8.encode(field.value);
  field.value = '';
  let envelope;
  try {
    if (plain.length === 0 || plain.length > 1048576) throw new Error('invalid input');
    const sender = await setupSender(from64(form.dataset.public), intakeInfo(form.dataset.request));
    envelope = {enc: to64(sender.enc), ciphertext: to64(await sender.seal(plain))};
  } catch {
    status.textContent = 'Input could not be encrypted. Reload this link to try again.';
    status.dataset.state = 'error';
    return;
  } finally {
    plain.fill(0);
  }
  try {
    status.textContent = 'Saving encrypted input…';
    const response = await fetch(location.pathname, {
      method: 'POST', credentials: 'omit', redirect: 'error',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify(envelope)
    });
    if (!response.ok) throw new Error('input rejected');
    const result = await response.json();
    if (typeof result.version !== 'string' || typeof result.fingerprint !== 'string') throw new Error('invalid result');
    document.querySelector('#version').textContent = result.version;
    document.querySelector('#fingerprint').textContent = result.fingerprint;
    document.querySelector('#result').hidden = false;
    form.hidden = true;
    status.textContent = 'Saved. This link can no longer be used.';
    status.dataset.state = 'success';
  } catch {
    status.textContent = 'Input was not confirmed. Check with the requester before using a new link.';
    status.dataset.state = 'error';
  }
});
