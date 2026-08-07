export const ITZF_MAGIC = 'ITZFENYXZ';
export const ITZF_VERSION = 4;
const HEADER_SIZE = 64;
const PREFIX_SIZE = 32;
const MAX_MANIFEST = 4 * 1024 * 1024;
const MAX_SOURCE = 256 * 1024 * 1024;
const enc = new TextEncoder();
const dec = new TextDecoder();
const keyParts = ['2b47e0f5c919', '::itzf-en-v2::', 'model-state-patch', '::63a1fd08'];

function assertFinite(n, label) {
  if (!Number.isFinite(n)) throw new Error(`${label} is not finite.`);
  return n;
}

export function identityTransform() {
  return { position: [0, 0, 0], rotation: [0, 0, 0, 1], scale: [1, 1, 1] };
}

export function cloneTransform(t) {
  return {
    position: [...(t?.position ?? [0, 0, 0])],
    rotation: [...(t?.rotation ?? [0, 0, 0, 1])],
    scale: [...(t?.scale ?? [1, 1, 1])]
  };
}

export function sanitizeObjectID(filename) {
  const base = String(filename || 'OBJECT').replace(/^.*[\\/]/, '').replace(/\.[^.]*$/, '');
  const cleaned = base.replace(/[^A-Za-z0-9_-]+/g, '_').replace(/^_+|_+$/g, '');
  return (cleaned || 'OBJECT').slice(0, 96);
}

function concatBytes(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// Pure-JavaScript SHA-256/HMAC. Keeping this inside the format implementation makes
// .itzfenyxz saving independent from WebCrypto/secure-context availability.
const SHA256_K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);
function rotr(x,n){return (x>>>n)|(x<<(32-n));}
function sha256(data) {
  const input = data instanceof Uint8Array ? data : new Uint8Array(data);
  const bitLen = input.length * 8;
  const total = Math.ceil((input.length + 9) / 64) * 64;
  const padded = new Uint8Array(total);
  padded.set(input); padded[input.length] = 0x80;
  const pdv = new DataView(padded.buffer);
  const high = Math.floor(bitLen / 0x100000000), low = bitLen >>> 0;
  pdv.setUint32(total - 8, high, false); pdv.setUint32(total - 4, low, false);
  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  const w = new Uint32Array(64);
  for(let off=0; off<total; off+=64){
    for(let i=0;i<16;i++) w[i]=pdv.getUint32(off+i*4,false);
    for(let i=16;i<64;i++){
      const a=w[i-15],b=w[i-2];
      const s0=rotr(a,7)^rotr(a,18)^(a>>>3), s1=rotr(b,17)^rotr(b,19)^(b>>>10);
      w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for(let i=0;i<64;i++){
      const S1=rotr(e,6)^rotr(e,11)^rotr(e,25), ch=(e&f)^((~e)&g);
      const t1=(h+S1+ch+SHA256_K[i]+w[i])>>>0;
      const S0=rotr(a,2)^rotr(a,13)^rotr(a,22), maj=(a&b)^(a&c)^(b&c);
      const t2=(S0+maj)>>>0;
      h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
    }
    h0=(h0+a)>>>0;h1=(h1+b)>>>0;h2=(h2+c)>>>0;h3=(h3+d)>>>0;
    h4=(h4+e)>>>0;h5=(h5+f)>>>0;h6=(h6+g)>>>0;h7=(h7+h)>>>0;
  }
  const out=new Uint8Array(32), odv=new DataView(out.buffer);
  [h0,h1,h2,h3,h4,h5,h6,h7].forEach((v,i)=>odv.setUint32(i*4,v,false));
  return out;
}
function signingRawKey(){ return sha256(enc.encode(keyParts.join(''))); }
function hmacSHA256(data) {
  let key=signingRawKey();
  if(key.length>64) key=sha256(key);
  const kb=new Uint8Array(64);kb.set(key);
  const innerPad=new Uint8Array(64),outerPad=new Uint8Array(64);
  for(let i=0;i<64;i++){innerPad[i]=kb[i]^0x36;outerPad[i]=kb[i]^0x5c;}
  const inner=sha256(concatBytes(innerPad,data));
  return sha256(concatBytes(outerPad,inner));
}

function normalizeTransform(t) {
  const out = identityTransform();
  if (t && Array.isArray(t.position) && t.position.length === 3) out.position = t.position.map((v, i) => assertFinite(Number(v), `position[${i}]`));
  if (t && Array.isArray(t.rotation) && t.rotation.length === 4) out.rotation = t.rotation.map((v, i) => assertFinite(Number(v), `rotation[${i}]`));
  if (t && Array.isArray(t.scale) && t.scale.length === 3) out.scale = t.scale.map((v, i) => assertFinite(Number(v), `scale[${i}]`));
  if (Math.hypot(...out.rotation) < 1e-12) out.rotation = [0, 0, 0, 1];
  const ql = Math.hypot(...out.rotation);
  out.rotation = out.rotation.map(v => v / ql);
  return out;
}

export function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

function normalizeVec3(value, fallback, label) {
  const src = Array.isArray(value) && value.length === 3 ? value : fallback;
  return src.map((v, i) => assertFinite(Number(v), `${label}[${i}]`));
}

function normalizeQuat(value, fallback = [0, 0, 0, 1]) {
  const src = Array.isArray(value) && value.length === 4 ? value.map(Number) : [...fallback];
  for (let i = 0; i < 4; i++) assertFinite(src[i], `quaternion[${i}]`);
  let len = Math.hypot(...src);
  if (len < 1e-12) return [0, 0, 0, 1];
  return src.map(v => v / len);
}

function normalizeColliderBase(collider = {}) {
  const legacyCenter = collider.baseCenter ?? collider.center ?? [0, 0, 0];
  const legacySize = collider.baseSize ?? collider.size ?? [1, 1, 1];
  const center = normalizeVec3(legacyCenter, [0, 0, 0], 'collider.baseCenter');
  const size = normalizeVec3(legacySize, [1, 1, 1], 'collider.baseSize')
    .map(v => Math.max(1e-7, Math.abs(v)));
  const rotation = normalizeQuat(collider.baseRotation ?? [0, 0, 0, 1]);
  return { center, size, rotation };
}

export function normalizeManifest(m = {}, sourceBytes = null) {
  const legacySourceName = String(m.sourceName || m.source?.name || 'model.3ds').slice(0, 260);
  const source = m.source ?? {};
  const colliderBase = normalizeColliderBase(m.collider ?? {});
  const sha = String(source.sha256 || '').toLowerCase();
  const token = String(source.token || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 5);

  return {
    format: ITZF_MAGIC,
    version: ITZF_VERSION,
    objectId: String(m.objectId || 'OBJECT').slice(0, 128),
    coordinateSystem: 'UNITY_LOCAL_Y_UP',
    source: {
      name: String(source.name || legacySourceName).slice(0, 260),
      format: '3ds',
      sha256: sha,
      token,
      calibrated: source.calibrated === true
    },
    // Kept in v4 for easier diagnostics and backwards tooling.
    sourceName: String(source.name || legacySourceName).slice(0, 260),
    sourceFormat: '3ds',
    root: normalizeTransform(m.root),
    visual: {
      present: m.visual?.present !== false,
      transform: normalizeTransform(m.visual?.transform)
    },
    collider: {
      apply: m.collider?.apply !== false,
      present: m.collider?.present !== false,
      type: 'box',
      baseCenter: colliderBase.center,
      baseSize: colliderBase.size,
      baseRotation: colliderBase.rotation,
      transform: normalizeTransform(m.collider?.transform)
    },
    editor: {
      savedAtUtc: new Date().toISOString(),
      generator: 'ITZFENYXZ Editor 0.9.2 Precision Pivot'
    }
  };
}

export async function encodeITZF(manifest, sourceBytes) {
  const src = sourceBytes instanceof Uint8Array ? sourceBytes : new Uint8Array(sourceBytes);
  if (!src.length || src.length > MAX_SOURCE) throw new Error('Embedded 3DS size is invalid.');

  const sourceHash = bytesToHex(sha256(src));
  const withSource = {
    ...manifest,
    source: {
      ...(manifest?.source ?? {}),
      name: manifest?.source?.name ?? manifest?.sourceName ?? 'model.3ds',
      format: '3ds',
      sha256: sourceHash
    }
  };

  const m = normalizeManifest(withSource, src);
  if (!m.objectId.trim()) throw new Error('Object ID is missing.');
  const mb = enc.encode(JSON.stringify(m));
  if (!mb.length || mb.length > MAX_MANIFEST) throw new Error('Manifest size is invalid.');

  const prefix = new Uint8Array(PREFIX_SIZE);
  const dv = new DataView(prefix.buffer);
  prefix.set(enc.encode(ITZF_MAGIC).subarray(0, 9), 0);
  dv.setUint16(12, ITZF_VERSION, true);
  dv.setUint16(14, 0, true);
  dv.setUint32(16, mb.length, true);
  dv.setUint32(20, src.length, true);
  const payload = concatBytes(mb, src);
  const sig = await hmacSHA256(concatBytes(prefix, payload));
  return concatBytes(prefix, sig, payload);
}

export async function decodeITZF(input) {
  const data = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (data.length < HEADER_SIZE) throw new Error('File is too small to be ITZFENYXZ.');
  const magic = dec.decode(data.subarray(0, 9));
  if (magic !== ITZF_MAGIC) throw new Error('Invalid ITZFENYXZ signature.');
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const version = dv.getUint16(12, true);
  if (version !== 2 && version !== 3 && version !== 4) throw new Error(`Unsupported ITZFENYXZ version ${version}.`);
  const ml = dv.getUint32(16, true);
  const sl = dv.getUint32(20, true);
  if (!ml || ml > MAX_MANIFEST) throw new Error('Invalid ITZFENYXZ manifest length.');
  if (!sl || sl > MAX_SOURCE) throw new Error('Invalid ITZFENYXZ source length.');
  if (data.length !== HEADER_SIZE + ml + sl) throw new Error('ITZFENYXZ file length does not match its header.');

  const prefix = data.subarray(0, PREFIX_SIZE);
  const stored = data.subarray(PREFIX_SIZE, HEADER_SIZE);
  const payload = data.subarray(HEADER_SIZE);
  const actual = await hmacSHA256(concatBytes(prefix, payload));
  if (stored.length !== actual.length || !stored.every((b, i) => b === actual[i])) throw new Error('ITZFENYXZ integrity check failed.');

  const rawManifest = JSON.parse(dec.decode(data.subarray(HEADER_SIZE, HEADER_SIZE + ml)));
  if (rawManifest.format !== ITZF_MAGIC) throw new Error('ITZFENYXZ manifest identity is invalid.');
  const sourceFormat = String(rawManifest.source?.format || rawManifest.sourceFormat || '').toLowerCase();
  if (sourceFormat !== '3ds') throw new Error(`Embedded source format ${sourceFormat || '(missing)'} is not supported.`);

  const source = data.slice(HEADER_SIZE + ml);
  if (version === 4) {
    const storedSourceHash = String(rawManifest.source?.sha256 || '').toLowerCase();
    const actualSourceHash = bytesToHex(sha256(source));
    if (!storedSourceHash || storedSourceHash !== actualSourceHash) throw new Error('Embedded 3DS source hash does not match the ITZFENYXZ manifest.');
  }

  const manifest = normalizeManifest(rawManifest, source);
  return { version, manifest, source };
}

// ---------- 3DS parser ----------
const CH = {
  M3D_MAGIC: 0x4d4d,
  MLIB_MAGIC: 0x3daa,
  C_MAGIC: 0xc23d,
  MDATA: 0x3d3d,
  MASTER_SCALE: 0x0100,
  NAMED_OBJECT: 0x4000,
  N_TRI_OBJECT: 0x4100,
  POINT_ARRAY: 0x4110,
  FACE_ARRAY: 0x4120,
  MSH_MAT_GROUP: 0x4130,
  TEX_VERTS: 0x4140,
  MESH_MATRIX: 0x4160
};

// Legacy marker support remains only so older sources can still be inspected.
const LEGACY = {
  ORIGIN: 'ITZO',
  AXIS_X: 'ITZX',
  AXIS_Y: 'ITZY',
  AXIS_Z: 'ITZZ',
  COLLIDER_CENTER: 'ITZCC',
  COLLIDER_X: 'ITZCX',
  COLLIDER_Y: 'ITZCY',
  COLLIDER_Z: 'ITZCZ',
  ID_PREFIX: 'ITZID'
};

const LEGACY_FIXED = [
  LEGACY.COLLIDER_CENTER,
  LEGACY.COLLIDER_X,
  LEGACY.COLLIDER_Y,
  LEGACY.COLLIDER_Z,
  LEGACY.ORIGIN,
  LEGACY.AXIS_X,
  LEGACY.AXIS_Y,
  LEGACY.AXIS_Z
];

const PROXY_FACE_TAGS = ['XP','XN','YP','YN','ZP','ZN'];
const PROXY_TOKEN_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const PROXY_UV_U_BASE = 9101;
const PROXY_UV_TOKEN_BASE = 9200;
const PROXY_UV_CHECKSUM_BASE = 9300;
const PROXY_UV_TOLERANCE = 0.08;

const COORDINATE_FRAME_NAME = 'ITZ_COORDINATE_FRAME';
const COORDINATE_FRAME_COMPONENTS = {
  origin: { vertices: 4, faces: 4 },
  x: { vertices: 5, faces: 6 },
  y: { vertices: 6, faces: 8 },
  z: { vertices: 8, faces: 12 }
};

const WELDED_PROXY_CORNER_U = [
  9104.0,
  9104.2,
  9103.8,
  9102.8,
  9103.4,
  9103.2,
  9103.6,
  9103.0
];

// Each row stores how many source vertices from the six proxy faces were
// welded into one logical cube corner by the FBX-to-3DS converter.
const WELDED_PROXY_FACE_COUNTS = [
  [0, 1, 0, 1, 0, 1],
  [1, 0, 0, 2, 0, 2],
  [0, 2, 1, 0, 0, 2],
  [2, 0, 2, 0, 0, 1],
  [0, 2, 0, 2, 1, 0],
  [2, 0, 0, 1, 2, 0],
  [0, 1, 2, 0, 2, 0],
  [1, 0, 1, 0, 1, 0]
];

const WELDED_PROXY_FACE_CORNERS = [
  [1, 3, 5, 7],
  [0, 2, 4, 6],
  [2, 3, 6, 7],
  [0, 1, 4, 5],
  [4, 5, 6, 7],
  [0, 1, 2, 3]
];

function solveLinearSystem(matrix, vector) {
  const size = vector.length;
  const augmented = matrix.map((row, index) => [...row, vector[index]]);

  for (let pivot = 0; pivot < size; pivot++) {
    let best = pivot;
    for (let row = pivot + 1; row < size; row++) {
      if (Math.abs(augmented[row][pivot]) > Math.abs(augmented[best][pivot])) {
        best = row;
      }
    }

    if (Math.abs(augmented[best][pivot]) < 1e-10) {
      return null;
    }

    if (best !== pivot) {
      const temporary = augmented[pivot];
      augmented[pivot] = augmented[best];
      augmented[best] = temporary;
    }

    const divisor = augmented[pivot][pivot];
    for (let column = pivot; column <= size; column++) {
      augmented[pivot][column] /= divisor;
    }

    for (let row = 0; row < size; row++) {
      if (row === pivot) continue;
      const factor = augmented[row][pivot];
      if (Math.abs(factor) < 1e-12) continue;
      for (let column = pivot; column <= size; column++) {
        augmented[row][column] -= factor * augmented[pivot][column];
      }
    }
  }

  return augmented.map(row => row[size]);
}

function solveLeastSquares(rows, values, unknownCount) {
  const normalMatrix = Array.from(
    { length: unknownCount },
    () => new Array(unknownCount).fill(0)
  );
  const normalVector = new Array(unknownCount).fill(0);

  for (let rowIndex = 0; rowIndex < rows.length; rowIndex++) {
    const row = rows[rowIndex];
    const value = values[rowIndex];

    for (let i = 0; i < unknownCount; i++) {
      normalVector[i] += row[i] * value;
      for (let j = 0; j < unknownCount; j++) {
        normalMatrix[i][j] += row[i] * row[j];
      }
    }
  }

  return solveLinearSystem(normalMatrix, normalVector);
}

function tryDecodeWeldedProxyObject(obj) {
  if (!obj ||
      obj.vertices?.length !== 8 ||
      obj.faces?.length !== 12 ||
      obj.uvs?.length !== 8) {
    return null;
  }

  const logicalCornerToVertex = new Array(8).fill(-1);
  const observedV = new Array(8).fill(0);

  for (let vertexIndex = 0; vertexIndex < 8; vertexIndex++) {
    const uv = obj.uvs[vertexIndex];
    if (!uv || !Number.isFinite(uv[0]) || !Number.isFinite(uv[1])) {
      return null;
    }

    let logicalCorner = -1;
    let bestDistance = Infinity;

    for (let corner = 0; corner < 8; corner++) {
      const distance = Math.abs(uv[0] - WELDED_PROXY_CORNER_U[corner]);
      if (distance < bestDistance) {
        bestDistance = distance;
        logicalCorner = corner;
      }
    }

    if (bestDistance > 0.08 ||
        logicalCorner < 0 ||
        logicalCornerToVertex[logicalCorner] >= 0) {
      return null;
    }

    logicalCornerToVertex[logicalCorner] = vertexIndex;
    observedV[logicalCorner] = uv[1];
  }

  if (logicalCornerToVertex.some(index => index < 0)) {
    return null;
  }

  const rows = WELDED_PROXY_FACE_COUNTS.map(counts => {
    const total = counts.reduce((sum, value) => sum + value, 0);
    return counts.map(value => value / total);
  });

  const metadataValues = solveLeastSquares(rows, observedV, 6);
  if (!metadataValues) {
    return null;
  }

  const tokenCharacters = [];
  for (let slot = 0; slot < 5; slot++) {
    const code = Math.round(metadataValues[slot] - PROXY_UV_TOKEN_BASE);
    if (code < 0 ||
        code >= PROXY_TOKEN_ALPHABET.length ||
        Math.abs(metadataValues[slot] - (PROXY_UV_TOKEN_BASE + code)) > 0.08) {
      return null;
    }
    tokenCharacters.push(PROXY_TOKEN_ALPHABET[code]);
  }

  const checksum = Math.round(metadataValues[5] - PROXY_UV_CHECKSUM_BASE);
  if (checksum < 0 ||
      checksum >= PROXY_TOKEN_ALPHABET.length ||
      Math.abs(metadataValues[5] - (PROXY_UV_CHECKSUM_BASE + checksum)) > 0.08) {
    return null;
  }

  const token = tokenCharacters.join('');
  const expectedChecksum = [...token].reduce(
    (sum, character) => sum + PROXY_TOKEN_ALPHABET.indexOf(character),
    0
  ) % PROXY_TOKEN_ALPHABET.length;

  if (checksum !== expectedChecksum) {
    return null;
  }

  for (let corner = 0; corner < 8; corner++) {
    const counts = WELDED_PROXY_FACE_COUNTS[corner];
    const total = counts.reduce((sum, value) => sum + value, 0);
    let predicted = 0;

    for (let face = 0; face < 6; face++) {
      predicted += metadataValues[face] * counts[face];
    }

    predicted /= total;
    if (Math.abs(predicted - observedV[corner]) > 0.08) {
      return null;
    }
  }

  return {
    obj,
    token,
    logicalCornerToVertex,
    metadataValues
  };
}

function readChunk(view, off, limit) {
  if (off < 0 || off + 6 > limit || limit > view.byteLength) {
    throw new Error('Truncated 3DS chunk header.');
  }
  const id = view.getUint16(off, true);
  const len = view.getUint32(off + 2, true);
  if (len < 6 || off + len > limit) {
    throw new Error(`Invalid 3DS chunk 0x${id.toString(16).padStart(4, '0')} length ${len}.`);
  }
  return { id, start: off, data: off + 6, end: off + len };
}

function readCString(bytes, off, limit) {
  let i = off;
  while (i < limit && bytes[i] !== 0) i++;
  if (i >= limit) throw new Error('Unterminated 3DS string.');
  return { text: dec.decode(bytes.subarray(off, i)), next: i + 1 };
}

function legacyToEditor(x, y, z) { return [x, z, -y]; }
function vAdd(a,b){return [a[0]+b[0],a[1]+b[1],a[2]+b[2]];}
function vSub(a,b){return [a[0]-b[0],a[1]-b[1],a[2]-b[2]];}
function vMul(a,s){return [a[0]*s,a[1]*s,a[2]*s];}
function vDot(a,b){return a[0]*b[0]+a[1]*b[1]+a[2]*b[2];}
function vCross(a,b){return [a[1]*b[2]-a[2]*b[1],a[2]*b[0]-a[0]*b[2],a[0]*b[1]-a[1]*b[0]];}
function vLen(a){return Math.hypot(a[0],a[1],a[2]);}
function vNorm(a){const l=vLen(a);if(l<1e-10)throw new Error('Degenerate ITZFENYXZ axis.');return [a[0]/l,a[1]/l,a[2]/l];}
function vAverage(points){if(!points.length)return [0,0,0];let s=[0,0,0];for(const p of points)s=vAdd(s,p);return vMul(s,1/points.length);}

function invert3x3Columns(x, y, z) {
  const det = vDot(x, vCross(y, z));
  if (!Number.isFinite(det) || Math.abs(det) < 1e-10) {
    throw new Error('ITZFENYXZ calibration markers are degenerate.');
  }
  const invDet = 1 / det;
  return {
    rows: [
      vCross(y, z).map(v => v * invDet),
      vCross(z, x).map(v => v * invDet),
      vCross(x, y).map(v => v * invDet)
    ],
    determinant: det
  };
}

function transformByInverseBasis(p, origin, inv) {
  const d = vSub(p, origin);
  return [vDot(inv.rows[0], d), vDot(inv.rows[1], d), vDot(inv.rows[2], d)];
}

function quatFromBasis(xAxis, yAxis, zAxis) {
  let x = vNorm(xAxis), y = vNorm(yAxis), z = vNorm(zAxis);
  y = vNorm(vSub(y, x.map(v => v * vDot(x, y))));
  z = vNorm(vCross(x, y));
  if (vDot(z, zAxis) < 0) z = z.map(v => -v);
  y = vNorm(vCross(z, x));

  const m00=x[0],m01=y[0],m02=z[0];
  const m10=x[1],m11=y[1],m12=z[1];
  const m20=x[2],m21=y[2],m22=z[2];
  const trace=m00+m11+m22;
  let q;
  if(trace>0){
    const s=Math.sqrt(trace+1)*2;
    q=[(m21-m12)/s,(m02-m20)/s,(m10-m01)/s,0.25*s];
  }else if(m00>m11&&m00>m22){
    const s=Math.sqrt(1+m00-m11-m22)*2;
    q=[0.25*s,(m01+m10)/s,(m02+m20)/s,(m21-m12)/s];
  }else if(m11>m22){
    const s=Math.sqrt(1+m11-m00-m22)*2;
    q=[(m01+m10)/s,0.25*s,(m12+m21)/s,(m02-m20)/s];
  }else{
    const s=Math.sqrt(1+m22-m00-m11)*2;
    q=[(m02+m20)/s,(m12+m21)/s,0.25*s,(m10-m01)/s];
  }
  return normalizeQuat(q);
}

function applyMeshMatrix(p, matrix) {
  if (!matrix) return [...p];
  const [x,y,z]=p;
  const ax=matrix.slice(0,3),ay=matrix.slice(3,6),az=matrix.slice(6,9),origin=matrix.slice(9,12);
  return [
    origin[0]+ax[0]*x+ay[0]*y+az[0]*z,
    origin[1]+ax[1]*x+ay[1]*y+az[1]*z,
    origin[2]+ax[2]*x+ay[2]*y+az[2]*z
  ];
}

function cloneObjectWithMatrixApplied(obj) {
  return { ...obj, vertices: obj.vertices.map(v => applyMeshMatrix(v, obj.meshMatrix)), meshMatrix: null };
}

function coordinateFrameCanonicalName(value) {
  return String(value || '').trim().toUpperCase().replace(/[^A-Z0-9]+/g, '');
}

function weldObjectTopology(obj, tolerance = 1e-5) {
  if (!obj || !obj.vertices?.length || !obj.faces?.length) return null;

  const scale = 1 / tolerance;
  const weldedPoints = [];
  const pointMap = new Map();
  const originalToWelded = new Array(obj.vertices.length).fill(-1);

  for (let i = 0; i < obj.vertices.length; i++) {
    const p = obj.vertices[i];
    if (!p?.every(Number.isFinite)) return null;
    const key = p.map(v => Math.round(v * scale)).join(',');
    let index = pointMap.get(key);
    if (index === undefined) {
      index = weldedPoints.length;
      pointMap.set(key, index);
      weldedPoints.push([...p]);
    }
    originalToWelded[i] = index;
  }

  const faceRecords = [];
  const adjacency = Array.from({ length: weldedPoints.length }, () => new Set());

  for (let fi = 0; fi < obj.faces.length; fi++) {
    const face = obj.faces[fi];
    if (!face || face.length !== 3) continue;
    const mapped = face.map(index => originalToWelded[index] ?? -1);
    if (mapped.some(index => index < 0)) continue;
    if (new Set(mapped).size < 3) continue;

    faceRecords.push({ faceIndex: fi, vertices: mapped });
    for (let i = 0; i < 3; i++) {
      const a = mapped[i], b = mapped[(i + 1) % 3];
      adjacency[a].add(b);
      adjacency[b].add(a);
    }
  }

  const visited = new Set();
  const components = [];

  for (let start = 0; start < weldedPoints.length; start++) {
    if (visited.has(start) || adjacency[start].size === 0) continue;

    const stack = [start];
    const vertexSet = new Set();
    visited.add(start);

    while (stack.length) {
      const current = stack.pop();
      vertexSet.add(current);
      for (const next of adjacency[current]) {
        if (visited.has(next)) continue;
        visited.add(next);
        stack.push(next);
      }
    }

    const faces = faceRecords.filter(record =>
      record.vertices.every(index => vertexSet.has(index))
    );

    if (!faces.length) continue;

    const points = [...vertexSet].map(index => weldedPoints[index]);
    const center = vAverage(points);

    components.push({
      vertexCount: vertexSet.size,
      faceCount: faces.length,
      center,
      faceIndices: faces.map(record => record.faceIndex),
      vertexIndices: [...vertexSet]
    });
  }

  return { weldedPoints, components };
}

function findGeometricCoordinateFrame(objects) {
  const candidates = [];

  for (const obj of objects) {
    const topology = weldObjectTopology(obj);
    if (!topology) continue;

    const roles = {};
    for (const [role, signature] of Object.entries(COORDINATE_FRAME_COMPONENTS)) {
      const matches = topology.components.filter(component =>
        component.vertexCount === signature.vertices &&
        component.faceCount === signature.faces
      );
      if (matches.length !== 1) continue;
      roles[role] = matches[0];
    }

    if (!roles.origin || !roles.x || !roles.y || !roles.z) continue;

    const O = roles.origin.center;
    const X = roles.x.center;
    const Y = roles.y.center;
    const Z = roles.z.center;

    const xBasis = vSub(X, O);
    const yBasis = vMul(vSub(Y, O), 0.5);
    const zBasis = vMul(vSub(Z, O), 1 / 3);

    let inverse;
    try {
      inverse = invert3x3Columns(xBasis, yBasis, zBasis);
    } catch {
      continue;
    }

    const map = point => transformByInverseBasis(point, O, inverse);
    const expected = [
      [roles.origin.center, [0, 0, 0]],
      [roles.x.center, [1, 0, 0]],
      [roles.y.center, [0, 2, 0]],
      [roles.z.center, [0, 0, 3]]
    ];

    let maximumError = 0;
    for (const [point, canonical] of expected) {
      maximumError = Math.max(maximumError, vLen(vSub(map(point), canonical)));
    }
    if (!Number.isFinite(maximumError) || maximumError > 1e-4) continue;

    const faceIndices = new Set([
      ...roles.origin.faceIndices,
      ...roles.x.faceIndices,
      ...roles.y.faceIndices,
      ...roles.z.faceIndices
    ]);

    const canonicalName = coordinateFrameCanonicalName(obj.name);
    const preferredName = canonicalName === coordinateFrameCanonicalName(COORDINATE_FRAME_NAME);
    const exactFaceCount = faceIndices.size === obj.faces.length;

    candidates.push({
      object: obj,
      origin: O,
      inverse,
      faceIndices,
      maximumError,
      preferredName,
      exactFaceCount,
      determinant: inverse.determinant
    });
  }

  if (!candidates.length) return null;

  candidates.sort((a, b) => {
    if (a.preferredName !== b.preferredName) return a.preferredName ? -1 : 1;
    if (a.exactFaceCount !== b.exactFaceCount) return a.exactFaceCount ? -1 : 1;
    return a.maximumError - b.maximumError;
  });

  if (candidates.length > 1) {
    const first = candidates[0], second = candidates[1];
    const equallyStrong =
      first.preferredName === second.preferredName &&
      first.exactFaceCount === second.exactFaceCount &&
      Math.abs(first.maximumError - second.maximumError) < 1e-8;
    if (equallyStrong) {
      throw new Error('Multiple ambiguous ITZFENYXZ coordinate calibration frames were found in the 3DS.');
    }
  }

  return candidates[0];
}


function rotateVectorByQuat(v, q) {
  const [x,y,z,w]=normalizeQuat(q);
  const uv=[y*v[2]-z*v[1],z*v[0]-x*v[2],x*v[1]-y*v[0]];
  const uuv=[y*uv[2]-z*uv[1],z*uv[0]-x*uv[2],x*uv[1]-y*uv[0]];
  return [
    v[0]+2*(w*uv[0]+uuv[0]),
    v[1]+2*(w*uv[1]+uuv[1]),
    v[2]+2*(w*uv[2]+uuv[2])
  ];
}

function exactBoxCorners(collider) {
  if (!collider) return [];
  const center=collider.center,size=collider.size,rotation=collider.rotation||[0,0,0,1];
  const h=size.map(v=>v/2),corners=[];
  for(let i=0;i<8;i++){
    const local=[i&1?h[0]:-h[0],i&2?h[1]:-h[1],i&4?h[2]:-h[2]];
    corners.push(vAdd(center,rotateVectorByQuat(local,rotation)));
  }
  return corners;
}

function uniqueMappedObjectPoints(obj,mapPoint,applyObjectMatrix=true) {
  const points=[],seen=new Set();
  for(const vertex of obj.vertices){
    const sourcePoint=applyObjectMatrix?applyMeshMatrix(vertex,obj.meshMatrix):vertex;
    const mapped=mapPoint(sourcePoint);
    const key=mapped.map(v=>Math.round(v*1e5)).join(',');
    if(seen.has(key))continue;
    seen.add(key);points.push(mapped);
  }
  return points;
}

function sortedPairwiseDistances(points) {
  const distances=[];
  for(let i=0;i<points.length;i++){
    for(let j=i+1;j<points.length;j++)distances.push(vLen(vSub(points[i],points[j])));
  }
  return distances.sort((a,b)=>a-b);
}

function distanceSignaturesMatch(a,b,tolerance) {
  if(a.length!==b.length)return false;
  for(let i=0;i<a.length;i++)if(Math.abs(a[i]-b[i])>tolerance)return false;
  return true;
}

function objectHasMaterialAssignments(obj) {
  return Array.isArray(obj?.faceMaterials)&&obj.faceMaterials.some(value=>String(value||'').trim().length>0);
}

function matchesColliderBoxShapeIgnoringPose(obj,mapPoint,colliderBase) {
  if(!obj||!colliderBase||!obj.vertices?.length||!obj.faces?.length)return false;
  if(obj.faces.length<10||obj.faces.length>24)return false;
  const expected=exactBoxCorners(colliderBase);
  if(expected.length!==8)return false;
  const expectedSignature=sortedPairwiseDistances(expected);
  const tolerance=Math.max(1e-4,Math.max(...colliderBase.size)*0.02);
  for(const applyObjectMatrix of [false,true]){
    const points=uniqueMappedObjectPoints(obj,mapPoint,applyObjectMatrix);
    if(points.length!==8)continue;
    if(distanceSignaturesMatch(sortedPairwiseDistances(points),expectedSignature,tolerance))return true;
  }
  return false;
}

function canonicalObjectRoleName(value) {
  return String(value||'').trim().toUpperCase().replace(/[^A-Z0-9]+/g,'');
}

function isReservedColliderGeometryName(value) {
  const name=canonicalObjectRoleName(value);
  return name==='COLLIDER'||name==='BOXCOLLIDER'||name==='COLLIDERMESH'||name==='COLLIDERGEOMETRY';
}

function looksLikeColliderHelperName(value) {
  const name=canonicalObjectRoleName(value);
  return /(?:COLLIDER|COLLISION|PHYSICS|HELPER|CUBE|BOX)/.test(name);
}

function matchesExactColliderGeometry(obj,mapPoint,colliderBase) {
  if(!obj||!colliderBase||!obj.vertices?.length||!obj.faces?.length)return false;
  if(obj.faces.length<10||obj.faces.length>24)return false;
  const points=uniqueMappedObjectPoints(obj,mapPoint,true);
  if(points.length!==8)return false;
  const expected=exactBoxCorners(colliderBase);
  if(expected.length!==8)return false;
  const tolerance=Math.max(1e-4,Math.max(...colliderBase.size)*0.0125);
  const used=new Set();
  for(const point of points){
    let best=-1,bestDistance=Infinity;
    for(let i=0;i<expected.length;i++){
      if(used.has(i))continue;
      const distance=vLen(vSub(point,expected[i]));
      if(distance<bestDistance){bestDistance=distance;best=i;}
    }
    if(best<0||bestDistance>tolerance)return false;
    used.add(best);
  }
  return used.size===8;
}

function canonicalNormalDirection(normal) {
  const n=[...normal];
  let largest=0;
  for(let i=1;i<3;i++)if(Math.abs(n[i])>Math.abs(n[largest]))largest=i;
  if(n[largest]<0)return n.map(value=>-value);
  return n;
}

function recoverColliderFromProxyGeometry(obj,mapPoint,referenceBounds=null) {
  if(!obj||!obj.vertices?.length||!obj.faces?.length)return null;

  function attempt(applyObjectMatrix){
    const mappedVertices=obj.vertices.map(vertex=>{
      const source=applyObjectMatrix?applyMeshMatrix(vertex,obj.meshMatrix):vertex;
      return mapPoint(source);
    });

    const unique=[];
    const seen=new Set();
    for(const point of mappedVertices){
      if(!point.every(Number.isFinite))return null;
      const key=point.map(value=>Math.round(value*1e5)).join(',');
      if(seen.has(key))continue;
      seen.add(key);
      unique.push(point);
    }
    if(unique.length!==8)return null;

    const groups=[];
    for(const face of obj.faces){
      if(!face||face.length!==3||face.some(index=>index<0||index>=mappedVertices.length))continue;
      const a=mappedVertices[face[0]],b=mappedVertices[face[1]],c=mappedVertices[face[2]];
      const cross=vCross(vSub(b,a),vSub(c,a));
      const area=vLen(cross);
      if(!Number.isFinite(area)||area<1e-10)continue;
      let normal=canonicalNormalDirection(vMul(cross,1/area));
      let group=groups.find(candidate=>Math.abs(vDot(candidate.direction,normal))>0.995);
      if(!group){
        group={sum:[0,0,0],weight:0,direction:normal};
        groups.push(group);
      }
      if(vDot(group.direction,normal)<0)normal=normal.map(value=>-value);
      group.sum=vAdd(group.sum,vMul(normal,area));
      group.weight+=area;
      group.direction=vNorm(group.sum);
    }

    if(groups.length<3)return null;

    let best=null;
    for(let i=0;i<groups.length;i++)for(let j=i+1;j<groups.length;j++)for(let k=j+1;k<groups.length;k++){
      const a=groups[i].direction,b=groups[j].direction,c=groups[k].direction;
      const orthogonality=Math.max(Math.abs(vDot(a,b)),Math.abs(vDot(a,c)),Math.abs(vDot(b,c)));
      if(orthogonality>0.03)continue;
      const score=groups[i].weight+groups[j].weight+groups[k].weight;
      if(!best||score>best.score)best={groups:[groups[i],groups[j],groups[k]],score};
    }
    if(!best)return null;

    let x=vNorm(best.groups[0].direction);
    let y=vNorm(vSub(best.groups[1].direction,vMul(x,vDot(x,best.groups[1].direction))));
    let z=vNorm(vCross(x,y));
    if(vDot(z,best.groups[2].direction)<0)z=z.map(value=>-value);
    y=vNorm(vCross(z,x));

    const axes=[x,y,z];
    const mins=[Infinity,Infinity,Infinity],maxs=[-Infinity,-Infinity,-Infinity];
    for(const point of unique){
      for(let axis=0;axis<3;axis++){
        const projection=vDot(point,axes[axis]);
        mins[axis]=Math.min(mins[axis],projection);
        maxs[axis]=Math.max(maxs[axis],projection);
      }
    }

    const size=maxs.map((value,index)=>value-mins[index]);
    if(!size.every(value=>Number.isFinite(value)&&value>1e-7))return null;

    const mids=mins.map((value,index)=>(value+maxs[index])*0.5);
    const center=vAdd(vAdd(vMul(x,mids[0]),vMul(y,mids[1])),vMul(z,mids[2]));
    const tolerance=Math.max(1e-4,Math.max(...size)*0.0125);
    const occupied=new Set();

    for(const point of unique){
      let corner=0;
      for(let axis=0;axis<3;axis++){
        const projection=vDot(point,axes[axis]);
        const distanceToMin=Math.abs(projection-mins[axis]);
        const distanceToMax=Math.abs(projection-maxs[axis]);
        if(Math.min(distanceToMin,distanceToMax)>tolerance)return null;
        if(distanceToMax<distanceToMin)corner|=(1<<axis);
      }
      occupied.add(corner);
    }
    if(occupied.size!==8)return null;

    return {
      center,
      size,
      rotation:quatFromBasis(x,y,z),
      fromProxy:true,
      recoveredFromGeometry:true,
      matrixApplied:applyObjectMatrix
    };
  }

  const bakedCandidate=attempt(false);
  const matrixCandidate=obj.meshMatrix?attempt(true):null;
  if(!bakedCandidate)return matrixCandidate;
  if(!matrixCandidate)return bakedCandidate;

  // Some converters bake the object transform into vertices and still emit a
  // non-identity MESH_MATRIX. Other converters leave the vertices local. Both
  // results are valid boxes, so choose the one that occupies the same space as
  // the visible model instead of blindly applying the matrix twice.
  if(referenceBounds){
    const bakedScore=colliderReferenceScore(bakedCandidate,referenceBounds);
    const matrixScore=colliderReferenceScore(matrixCandidate,referenceBounds);
    return matrixScore>bakedScore+0.05?matrixCandidate:bakedCandidate;
  }
  // Visible Geometry in this editor is interpreted as baked by default.
  return bakedCandidate;
}

function canonicalLegacyMarkerName(value) {
  const original = String(value || '').trim().toUpperCase();
  if (!original) return '';
  const idMatch = original.match(/ITZID([A-Z0-9]{5})/);
  if (idMatch) return `${LEGACY.ID_PREFIX}${idMatch[1]}`;

  for (const marker of LEGACY_FIXED) {
    if (original === marker) return marker;
    const escaped = marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const boundary = new RegExp(`(?:^|[^A-Z0-9])${escaped}(?:$|[^A-Z0-9])`);
    if (boundary.test(original)) return marker;
    const pos = original.lastIndexOf(marker);
    if (pos < 0) continue;
    const beforeIsBoundary = pos === 0 || /[^A-Z0-9]$/.test(original.slice(0,pos));
    const suffix = original.slice(pos + marker.length).replace(/[^A-Z0-9]/g, '');
    if (beforeIsBoundary && (suffix === '' || /^(?:\d+|MESH\d*|OBJECT\d*|MAT\d*)$/.test(suffix))) return marker;
  }
  return '';
}

function parseProxyObjectToken(value) {
  const text = String(value || '').trim().toUpperCase();
  const match = text.match(/(?:^|[^A-Z0-9])IC([A-Z0-9]{5})(?:$|[^A-Z0-9])/)
    || text.match(/^IC([A-Z0-9]{5})$/)
    || text.match(/IC([A-Z0-9]{5})(?:\d+|MESH\d*|OBJECT\d*)$/);
  return match ? match[1] : '';
}

function decodeProxyUvFace(obj, faceIndex) {
  if (!obj || !Array.isArray(obj.faces) || !Array.isArray(obj.uvs)) return null;
  if (obj.uvs.length !== obj.vertices.length) return null;
  const face = obj.faces[faceIndex];
  if (!face || face.length !== 3) return null;

  const points=[];
  for(const index of face){
    if(index<0||index>=obj.uvs.length)return null;
    const uv=obj.uvs[index];
    if(!uv||!Number.isFinite(uv[0])||!Number.isFinite(uv[1]))return null;
    points.push(uv);
  }

  const averageU=(points[0][0]+points[1][0]+points[2][0])/3;
  const averageV=(points[0][1]+points[1][1]+points[2][1])/3;
  const slot=Math.round(averageU-PROXY_UV_U_BASE);
  if(slot<0||slot>=PROXY_FACE_TAGS.length)return null;
  const expectedU=PROXY_UV_U_BASE+slot;
  if(Math.abs(averageU-expectedU)>PROXY_UV_TOLERANCE)return null;
  for(const uv of points){
    if(Math.abs(uv[0]-expectedU)>PROXY_UV_TOLERANCE||
       Math.abs(uv[1]-averageV)>PROXY_UV_TOLERANCE)return null;
  }

  if(slot<5){
    const code=Math.round(averageV-PROXY_UV_TOKEN_BASE);
    if(code<0||code>=PROXY_TOKEN_ALPHABET.length)return null;
    if(Math.abs(averageV-(PROXY_UV_TOKEN_BASE+code))>PROXY_UV_TOLERANCE)return null;
    return {tag:PROXY_FACE_TAGS[slot],slot,tokenCharacter:PROXY_TOKEN_ALPHABET[code],checksum:null};
  }

  const checksum=Math.round(averageV-PROXY_UV_CHECKSUM_BASE);
  if(checksum<0||checksum>=PROXY_TOKEN_ALPHABET.length)return null;
  if(Math.abs(averageV-(PROXY_UV_CHECKSUM_BASE+checksum))>PROXY_UV_TOLERANCE)return null;
  return {tag:PROXY_FACE_TAGS[slot],slot,tokenCharacter:'',checksum};
}

function objectCenter(obj) {
  if (!obj.vertices.length) throw new Error(`Reserved marker ${obj.name} has no vertices.`);
  const min=[Infinity,Infinity,Infinity],max=[-Infinity,-Infinity,-Infinity];
  for(const p of obj.vertices)for(let a=0;a<3;a++){min[a]=Math.min(min[a],p[a]);max[a]=Math.max(max[a],p[a]);}
  return min.map((v,i)=>(v+max[i])/2);
}

function findLegacyNamed(objects, name) {
  const wanted = canonicalLegacyMarkerName(name) || String(name || '').toUpperCase();
  return objects.find(o => canonicalLegacyMarkerName(o.name) === wanted) ?? null;
}

function scanLegacyMarkers(objects) {
  const markers=[];
  let markerObjectsByName=0,markerMaterialGroups=0;
  for(const obj of objects){
    const objectName=canonicalLegacyMarkerName(obj.name);
    if(objectName){
      markers.push({...obj,name:objectName,markerSource:'object-name'});
      markerObjectsByName++;
    }
    const groups=new Map();
    for(let fi=0;fi<obj.faces.length;fi++){
      const markerName=canonicalLegacyMarkerName(obj.faceMaterials?.[fi]);
      if(!markerName)continue;
      if(!groups.has(markerName))groups.set(markerName,new Set());
      for(const vi of obj.faces[fi])if(vi>=0&&vi<obj.vertices.length)groups.get(markerName).add(vi);
    }
    for(const [name,indices] of groups){
      markers.push({name,vertices:[...indices].map(i=>obj.vertices[i]),faces:[],uvs:[],faceMaterials:[],meshMatrix:obj.meshMatrix,markerSource:'material-group'});
      markerMaterialGroups++;
    }
  }
  return {markers,markerObjectsByName,markerMaterialGroups};
}

function parseLegacyIdentityToken(objects) {
  const tokens=[];
  for(const obj of objects){
    const name=canonicalLegacyMarkerName(obj.name);
    if(!name.startsWith(LEGACY.ID_PREFIX))continue;
    const token=name.slice(LEGACY.ID_PREFIX.length);
    if(/^[A-Z0-9]{5}$/.test(token))tokens.push(token);
  }
  const unique=[...new Set(tokens)];
  if(!unique.length)return '';
  if(unique.length!==1)throw new Error('Multiple conflicting ITZFENYXZ source identity markers were found.');
  return unique[0];
}

function parseLegacyCalibration(objects) {
  const o=findLegacyNamed(objects,LEGACY.ORIGIN),x=findLegacyNamed(objects,LEGACY.AXIS_X),y=findLegacyNamed(objects,LEGACY.AXIS_Y),z=findLegacyNamed(objects,LEGACY.AXIS_Z);
  if(!o&&!x&&!y&&!z)return null;
  if(!o||!x||!y||!z)throw new Error('Incomplete legacy ITZFENYXZ calibration markers.');
  const O=objectCenter(o),X=objectCenter(x),Y=objectCenter(y),Z=objectCenter(z);
  return {origin:O,inverse:invert3x3Columns(vSub(X,O),vSub(Y,O),vSub(Z,O))};
}

function parseLegacyCollider(objects,mapPoint){
  const c=findLegacyNamed(objects,LEGACY.COLLIDER_CENTER),x=findLegacyNamed(objects,LEGACY.COLLIDER_X),y=findLegacyNamed(objects,LEGACY.COLLIDER_Y),z=findLegacyNamed(objects,LEGACY.COLLIDER_Z);
  if(!c&&!x&&!y&&!z)return null;
  if(!c||!x||!y||!z)throw new Error('Incomplete legacy ITZFENYXZ collider markers.');
  const C=mapPoint(objectCenter(c)),X=mapPoint(objectCenter(x)),Y=mapPoint(objectCenter(y)),Z=mapPoint(objectCenter(z));
  const vx=vSub(X,C),vy=vSub(Y,C),vz=vSub(Z,C);
  const size=[2*vLen(vx),2*vLen(vy),2*vLen(vz)];
  if(Math.min(...size)<1e-7)throw new Error('Legacy collider markers describe a zero-sized BoxCollider.');
  const nx=vNorm(vx),ny=vNorm(vy),nz=vNorm(vz);
  const shear=Math.max(Math.abs(vDot(nx,ny)),Math.abs(vDot(nx,nz)),Math.abs(vDot(ny,nz)));
  if(shear>0.01)throw new Error('Legacy BoxCollider markers contain shear.');
  return {center:C,size,rotation:quatFromBasis(nx,ny,nz),fromProxy:false};
}

function scanColliderProxy(objects) {
  const namedTokens=new Set();
  const namedProxyObjects=new Set();
  const taggedFaces=[];
  const tokenCharacters=new Array(5).fill('');
  const weldedCandidates=[];
  let checksum=null;
  let proxyObjectCount=0;
  let proxyFaceCount=0;

  for(const obj of objects){
    const objectToken=parseProxyObjectToken(obj.name);
    if(objectToken){
      namedTokens.add(objectToken);
      namedProxyObjects.add(obj);
      proxyObjectCount++;
    }

    const welded=tryDecodeWeldedProxyObject(obj);
    if(welded)weldedCandidates.push(welded);

    for(let fi=0;fi<obj.faces.length;fi++){
      const metadata=decodeProxyUvFace(obj,fi);
      if(!metadata)continue;
      taggedFaces.push({obj,faceIndex:fi,tag:metadata.tag,slot:metadata.slot});
      proxyFaceCount++;

      if(metadata.slot<5){
        const previous=tokenCharacters[metadata.slot];
        if(previous&&previous!==metadata.tokenCharacter){
          throw new Error('Conflicting ITZFENYXZ collider-proxy UV token data was found.');
        }
        tokenCharacters[metadata.slot]=metadata.tokenCharacter;
      }else{
        if(checksum!==null&&checksum!==metadata.checksum){
          throw new Error('Conflicting ITZFENYXZ collider-proxy UV checksum data was found.');
        }
        checksum=metadata.checksum;
      }
    }
  }

  if(!taggedFaces.length&&weldedCandidates.length){
    if(weldedCandidates.length>1){
      const tokens=[...new Set(weldedCandidates.map(candidate=>candidate.token))];
      if(tokens.length!==1){
        throw new Error('Multiple conflicting welded ITZFENYXZ collider proxies were found.');
      }
      throw new Error('Multiple welded ITZFENYXZ collider proxy objects were found.');
    }

    const welded=weldedCandidates[0];

    if(namedTokens.size>1){
      throw new Error('Conflicting ITZFENYXZ collider proxy identity tokens were found.');
    }

    if(namedTokens.size){
      const namedToken=[...namedTokens][0];
      if(namedToken!==welded.token){
        throw new Error('The collider proxy object name does not match its welded UV identity token.');
      }
    }

    return {
      token:welded.token,
      taggedFaces:[],
      proxyObjectCount:1,
      proxyFaceCount:welded.obj.faces.length,
      weldedProxy:welded,
      proxyObjects:new Set([welded.obj])
    };
  }

  if(!namedTokens.size&&!taggedFaces.length)return null;
  if(namedTokens.size>1)throw new Error('Conflicting ITZFENYXZ collider proxy identity tokens were found.');

  const metadataComplete=!tokenCharacters.some(character=>!character)&&checksum!==null;
  if(!metadataComplete){
    // Several FBX-to-3DS converters preserve the dedicated ICxxxxx object and
    // its exact box geometry but weld, average, clamp or partly discard its UVs.
    // The object name already contains the authenticated five-character source
    // token, so recover the collider from the six box faces instead of rejecting
    // an otherwise valid source.
    if(namedTokens.size===1&&namedProxyObjects.size){
      const namedToken=[...namedTokens][0];

      for(let slot=0;slot<5;slot++){
        if(tokenCharacters[slot]&&tokenCharacters[slot]!==namedToken[slot]){
          throw new Error('The collider proxy object name conflicts with the surviving UV identity metadata.');
        }
      }

      const expectedChecksum=[...namedToken].reduce(
        (sum,character)=>sum+PROXY_TOKEN_ALPHABET.indexOf(character),0
      )%PROXY_TOKEN_ALPHABET.length;

      if(checksum!==null&&checksum!==expectedChecksum){
        throw new Error('The collider proxy object name conflicts with the surviving UV checksum metadata.');
      }

      return {
        token:namedToken,
        taggedFaces,
        proxyObjectCount,
        proxyFaceCount,
        proxyObjects:new Set(namedProxyObjects),
        geometryFallback:true
      };
    }

    const taggedObjects=new Set(taggedFaces.map(reference=>reference.obj));
    if(taggedObjects.size===1){
      const partialTokenComplete=!tokenCharacters.some(character=>!character);
      const recoveredToken=partialTokenComplete?tokenCharacters.join(''):'';
      if(recoveredToken&&checksum!==null){
        const recoveredChecksum=[...recoveredToken].reduce(
          (sum,character)=>sum+PROXY_TOKEN_ALPHABET.indexOf(character),0
        )%PROXY_TOKEN_ALPHABET.length;
        if(checksum!==recoveredChecksum){
          throw new Error('The surviving collider proxy UV checksum is invalid.');
        }
      }
      return {
        token:recoveredToken,
        taggedFaces,
        proxyObjectCount:taggedObjects.size,
        proxyFaceCount,
        proxyObjects:taggedObjects,
        geometryFallback:true,
        partialUvFallback:true
      };
    }

    throw new Error('The collider proxy UV metadata is incomplete and no single box proxy object survived the 3DS conversion.');
  }

  const token=tokenCharacters.join('');
  const expectedChecksum=[...token].reduce((sum,character)=>sum+PROXY_TOKEN_ALPHABET.indexOf(character),0)%PROXY_TOKEN_ALPHABET.length;
  if(checksum!==expectedChecksum){
    throw new Error('The collider proxy UV checksum is invalid. The proxy was altered during conversion.');
  }

  if(namedTokens.size){
    const namedToken=[...namedTokens][0];
    if(namedToken!==token){
      throw new Error('The collider proxy object name does not match its UV identity token.');
    }
  }

  const proxyObjects=new Set(namedProxyObjects);

  return {token,taggedFaces,proxyObjectCount,proxyFaceCount,proxyObjects};
}

function uniqueMappedFacePoints(faceRefs, tag, mapPoint, applyObjectMatrix=true) {
  const points=[];
  const seen=new Set();
  for(const ref of faceRefs){
    if(ref.tag!==tag)continue;
    const face=ref.obj.faces[ref.faceIndex];
    if(!face)continue;
    for(const index of face){
      if(index<0||index>=ref.obj.vertices.length)continue;
      const sourcePoint=applyObjectMatrix?applyMeshMatrix(ref.obj.vertices[index],ref.obj.meshMatrix):ref.obj.vertices[index];
      const mapped=mapPoint(sourcePoint);
      const key=mapped.map(v=>Math.round(v*1e6)).join(',');
      if(seen.has(key))continue;
      seen.add(key);points.push(mapped);
    }
  }
  return points;
}

function createWeldedProxyCoordinateMap(welded) {
  if(!welded)return null;

  const corners=welded.logicalCornerToVertex.map(vertexIndex=>{
    if(vertexIndex<0||vertexIndex>=welded.obj.vertices.length){
      throw new Error('The welded collider proxy corner map is invalid.');
    }
    return welded.obj.vertices[vertexIndex];
  });

  const centers=WELDED_PROXY_FACE_CORNERS.map(indices=>
    vAverage(indices.map(corner=>corners[corner]))
  );

  let nx=vNorm(vSub(centers[0],centers[1]));
  const ny=vNorm(vSub(centers[2],centers[3]));
  const nz=vNorm(vSub(centers[4],centers[5]));

  const shear=Math.max(
    Math.abs(vDot(nx,ny)),
    Math.abs(vDot(nx,nz)),
    Math.abs(vDot(ny,nz))
  );

  if(shear>0.01){
    throw new Error('The welded collider proxy cannot recover a stable source coordinate system.');
  }

  const handedness=vDot(vCross(ny,nz),nx);
  if(Math.abs(handedness)<0.98){
    throw new Error('The welded collider proxy coordinate axes are degenerate.');
  }

  // The converter used for the uploaded 3DS reverses one axis while welding
  // the proxy. Axis sign does not change a BoxCollider, so choose the sign that
  // produces a proper right-handed editor basis instead of rotating Y into Z.
  if(handedness<0)nx=nx.map(value=>-value);

  return point=>[
    vDot(nx,point),
    vDot(ny,point),
    vDot(nz,point)
  ];
}


function mappedObjectBounds(obj,mapPoint,applyObjectMatrix=false){
  if(!obj?.vertices?.length)return null;
  const min=[Infinity,Infinity,Infinity],max=[-Infinity,-Infinity,-Infinity];
  for(const vertex of obj.vertices){
    const source=applyObjectMatrix?applyMeshMatrix(vertex,obj.meshMatrix):vertex;
    const point=mapPoint(source);
    if(!point.every(Number.isFinite))return null;
    for(let axis=0;axis<3;axis++){
      min[axis]=Math.min(min[axis],point[axis]);
      max[axis]=Math.max(max[axis],point[axis]);
    }
  }
  return {min,max,center:min.map((value,index)=>(value+max[index])*0.5),size:max.map((value,index)=>value-min[index])};
}

function colliderBounds(collider){
  const corners=exactBoxCorners(collider);
  if(!corners.length)return null;
  const min=[Infinity,Infinity,Infinity],max=[-Infinity,-Infinity,-Infinity];
  for(const point of corners)for(let axis=0;axis<3;axis++){
    min[axis]=Math.min(min[axis],point[axis]);
    max[axis]=Math.max(max[axis],point[axis]);
  }
  return {min,max,center:min.map((value,index)=>(value+max[index])*0.5),size:max.map((value,index)=>value-min[index])};
}


function combinedMappedBounds(objects,mapPoint,excludedObjects=new Set()){
  const min=[Infinity,Infinity,Infinity],max=[-Infinity,-Infinity,-Infinity];
  let count=0;
  for(const obj of objects||[]){
    if(excludedObjects?.has(obj)||!obj?.vertices?.length)continue;
    for(const vertex of obj.vertices){
      const point=mapPoint(vertex);
      if(!point.every(Number.isFinite))continue;
      count++;
      for(let axis=0;axis<3;axis++){
        min[axis]=Math.min(min[axis],point[axis]);
        max[axis]=Math.max(max[axis],point[axis]);
      }
    }
  }
  if(!count)return null;
  return {min,max,center:min.map((value,index)=>(value+max[index])*0.5),size:max.map((value,index)=>value-min[index])};
}

function colliderReferenceScore(collider,referenceBounds){
  const bounds=colliderBounds(collider);
  if(!bounds||!referenceBounds)return -Infinity;
  const diagonal=Math.max(1e-6,vLen(referenceBounds.size));
  const centerScore=Math.max(0,1-vLen(vSub(bounds.center,referenceBounds.center))/diagonal);
  const overlapScore=boundsIntersectionRatio(bounds,referenceBounds);
  const longestCollider=Math.max(...collider.size);
  const longestReference=Math.max(...referenceBounds.size,1e-6);
  const lengthScore=Math.max(0,1-Math.abs(Math.log(longestCollider/longestReference))/Math.log(4));
  return overlapScore*4+centerScore*2+lengthScore;
}

function boundsIntersectionRatio(a,b){
  if(!a||!b)return 0;
  let intersection=1,smaller=1;
  for(let axis=0;axis<3;axis++){
    const overlap=Math.max(0,Math.min(a.max[axis],b.max[axis])-Math.max(a.min[axis],b.min[axis]));
    intersection*=overlap;
    smaller*=Math.max(1e-9,Math.min(a.size[axis],b.size[axis]));
  }
  return intersection/smaller;
}

function findEndpointColliderProxy(objects,mapPoint){
  const candidates=[];
  for(const obj of objects){
    if(!obj?.vertices?.length||!obj?.faces?.length)continue;
    if(obj.faces.length<10||obj.faces.length>24)continue;
    const recovered=recoverColliderFromProxyGeometry(obj,mapPoint);
    if(!recovered)continue;
    candidates.push({obj,recovered,bounds:colliderBounds(recovered)});
  }
  if(!candidates.length)return null;

  // A real export proxy is a tiny twelve-triangle helper next to substantially
  // more detailed visible Geometry. This prevents ordinary box-shaped models
  // from being silently mistaken for collider metadata.
  const detailedObjects=objects.filter(obj=>
    obj?.vertices?.length&&obj?.faces?.length&&
    !candidates.some(candidate=>candidate.obj===obj)&&
    (obj.faces.length>24||obj.vertices.length>16)
  );
  if(!detailedObjects.length)return null;

  let best=null;
  const scored=[];
  for(const candidate of candidates){
    const restPoints=[];
    for(const obj of objects){
      if(obj===candidate.obj||!obj?.vertices?.length)continue;
      for(const vertex of obj.vertices){
        const point=mapPoint(vertex);
        if(point.every(Number.isFinite))restPoints.push(point);
      }
    }
    if(!restPoints.length)continue;
    const restMin=[Infinity,Infinity,Infinity],restMax=[-Infinity,-Infinity,-Infinity];
    for(const point of restPoints)for(let axis=0;axis<3;axis++){
      restMin[axis]=Math.min(restMin[axis],point[axis]);
      restMax[axis]=Math.max(restMax[axis],point[axis]);
    }
    const rest={
      min:restMin,
      max:restMax,
      center:restMin.map((value,index)=>(value+restMax[index])*0.5),
      size:restMax.map((value,index)=>value-restMin[index])
    };
    const diagonal=Math.max(1e-6,vLen(rest.size));
    const centerScore=Math.max(0,1-vLen(vSub(candidate.bounds.center,rest.center))/diagonal);
    const overlapScore=boundsIntersectionRatio(candidate.bounds,rest);
    const longestCandidate=Math.max(...candidate.recovered.size);
    const longestRest=Math.max(...rest.size,1e-6);
    const lengthScore=Math.max(0,1-Math.abs(Math.log(longestCandidate/longestRest))/Math.log(4));
    const score=overlapScore*4+centerScore*2+lengthScore;
    const scoredCandidate={...candidate,score};
    scored.push(scoredCandidate);
    if(!best||score>best.score)best=scoredCandidate;
  }

  if(!best||best.score<2.15)return null;
  const second=scored
    .filter(candidate=>candidate.obj!==best.obj)
    .map(candidate=>candidate.score)
    .sort((a,b)=>b-a)[0];
  if(Number.isFinite(second)&&best.score-second<0.15)return null;

  return {
    token:parseProxyObjectToken(best.obj.name)||'',
    taggedFaces:[],
    proxyObjectCount:1,
    proxyFaceCount:best.obj.faces.length,
    proxyObjects:new Set([best.obj]),
    geometryFallback:true,
    endpointFallback:true,
    recoveredCollider:best.recovered
  };
}

function parseExactColliderProxy(scan,mapPoint,objects=[]) {
  if(!scan)return null;
  if(scan.token&&!/^[A-Z0-9]{5}$/.test(scan.token))throw new Error('The collider proxy has an invalid five-character source token.');
  if(!scan.token&&!scan.geometryFallback)throw new Error('The collider proxy has no valid five-character source token.');

  if(scan.geometryFallback){
    const referenceBounds=combinedMappedBounds(objects,mapPoint,scan.proxyObjects||new Set());
    if(scan.recoveredCollider){
      const collider=recoverColliderFromProxyGeometry(
        [...(scan.proxyObjects||[])][0],mapPoint,referenceBounds
      )||scan.recoveredCollider;
      return {...collider,token:scan.token||''};
    }
    const recovered=[];
    for(const obj of scan.proxyObjects||[]){
      const collider=recoverColliderFromProxyGeometry(obj,mapPoint,referenceBounds);
      if(collider)recovered.push(collider);
    }
    if(!recovered.length){
      throw new Error('The ICxxxxx collider proxy was found, but its box geometry could not be recovered after 3DS conversion.');
    }
    if(recovered.length>1){
      const first=recovered[0];
      const tolerance=Math.max(1e-4,Math.max(...first.size)*0.02);
      for(let i=1;i<recovered.length;i++){
        if(vLen(vSub(first.center,recovered[i].center))>tolerance){
          throw new Error('Multiple conflicting collider proxy boxes were found.');
        }
      }
    }
    return {...recovered[0],token:scan.token};
  }

  if(scan.weldedProxy){
    const welded=scan.weldedProxy;
    const corners=welded.logicalCornerToVertex.map(vertexIndex=>{
      if(vertexIndex<0||vertexIndex>=welded.obj.vertices.length){
        throw new Error('The welded collider proxy corner map is invalid.');
      }

      // This FBX-to-3DS converter already bakes the exported object pose into
      // the vertex coordinates and leaves MESH_MATRIX only as a local-axis
      // descriptor. Applying it again is what rotated the model downward.
      return mapPoint(welded.obj.vertices[vertexIndex]);
    });

    const centers={};
    for(let faceIndex=0;faceIndex<PROXY_FACE_TAGS.length;faceIndex++){
      const tag=PROXY_FACE_TAGS[faceIndex];
      centers[tag]=vAverage(
        WELDED_PROXY_FACE_CORNERS[faceIndex].map(corner=>corners[corner])
      );
    }

    const vx=vSub(centers.XP,centers.XN);
    const vy=vSub(centers.YP,centers.YN);
    const vz=vSub(centers.ZP,centers.ZN);
    const size=[vLen(vx),vLen(vy),vLen(vz)];
    if(Math.min(...size)<1e-7)throw new Error('The welded exact collider proxy describes a zero-sized BoxCollider.');

    let nx=vNorm(vx),ny=vNorm(vy),nz=vNorm(vz);
    const shear=Math.max(Math.abs(vDot(nx,ny)),Math.abs(vDot(nx,nz)),Math.abs(vDot(ny,nz)));
    if(shear>0.01)throw new Error('The welded exact collider proxy was distorted into a sheared box during conversion.');

    const handedness=vDot(vCross(ny,nz),nx);
    if(Math.abs(handedness)<0.98){
      throw new Error('The welded exact collider proxy axes are not orthogonal.');
    }

    // Axis signs do not change the physical box. Some converters reverse one
    // axis while welding the 36 proxy vertices into 8 shared corners.
    if(handedness<0)nx=nx.map(value=>-value);

    const midX=vMul(vAdd(centers.XP,centers.XN),0.5);
    const midY=vMul(vAdd(centers.YP,centers.YN),0.5);
    const midZ=vMul(vAdd(centers.ZP,centers.ZN),0.5);
    const center=vAverage([midX,midY,midZ]);
    const centerError=Math.max(vLen(vSub(midX,center)),vLen(vSub(midY,center)),vLen(vSub(midZ,center)));
    if(centerError>Math.max(...size)*0.01+1e-4)throw new Error('The welded exact collider proxy faces no longer share the same center.');

    return {
      center,
      size,
      rotation:quatFromBasis(nx,ny,nz),
      fromProxy:true,
      token:scan.token,
      welded:true
    };
  }

  if(!scan.taggedFaces.length){
    throw new Error('The collider proxy object was found, but its reserved UV metadata was lost during FBX-to-3DS conversion.');
  }

  function recoverTaggedProxy(applyObjectMatrix){
    const centers={};
    for(const tag of PROXY_FACE_TAGS){
      const points=uniqueMappedFacePoints(scan.taggedFaces,tag,mapPoint,applyObjectMatrix);
      if(points.length<3)throw new Error(`Collider proxy side I${tag}${scan.token} is missing or incomplete.`);
      centers[tag]=vAverage(points);
    }

    const vx=vSub(centers.XP,centers.XN);
    const vy=vSub(centers.YP,centers.YN);
    const vz=vSub(centers.ZP,centers.ZN);
    const size=[vLen(vx),vLen(vy),vLen(vz)];
    if(Math.min(...size)<1e-7)throw new Error('The exact collider proxy describes a zero-sized BoxCollider.');

    let nx=vNorm(vx),ny=vNorm(vy),nz=vNorm(vz);
    const shear=Math.max(Math.abs(vDot(nx,ny)),Math.abs(vDot(nx,nz)),Math.abs(vDot(ny,nz)));
    if(shear>0.01)throw new Error('The exact collider proxy was distorted into a sheared box during conversion.');
    const handedness=vDot(vCross(ny,nz),nx);
    if(Math.abs(handedness)<0.98)throw new Error('The exact collider proxy axes are not orthogonal after conversion.');
    if(handedness<0)nx=nx.map(value=>-value);

    const midX=vMul(vAdd(centers.XP,centers.XN),0.5);
    const midY=vMul(vAdd(centers.YP,centers.YN),0.5);
    const midZ=vMul(vAdd(centers.ZP,centers.ZN),0.5);
    const center=vAverage([midX,midY,midZ]);
    const centerError=Math.max(vLen(vSub(midX,center)),vLen(vSub(midY,center)),vLen(vSub(midZ,center)));
    if(centerError>Math.max(...size)*0.01+1e-4)throw new Error('The exact collider proxy faces no longer share the same center.');

    return {center,size,rotation:quatFromBasis(nx,ny,nz),fromProxy:true,token:scan.token,matrixApplied:applyObjectMatrix};
  }

  const referenceBounds=combinedMappedBounds(objects,mapPoint,scan.proxyObjects||new Set());
  const candidates=[];
  const errors=[];
  for(const applyObjectMatrix of [false,true]){
    if(applyObjectMatrix&&!scan.taggedFaces.some(reference=>reference.obj.meshMatrix))continue;
    try{
      const candidate=recoverTaggedProxy(applyObjectMatrix);
      if(!candidates.some(existing=>
        vLen(vSub(existing.center,candidate.center))<1e-5&&
        existing.size.every((value,index)=>Math.abs(value-candidate.size[index])<1e-5)
      ))candidates.push(candidate);
    }catch(error){errors.push(error);}
  }
  if(!candidates.length)throw errors[0]||new Error('The exact collider proxy could not be recovered.');
  if(candidates.length===1)return candidates[0];
  candidates.sort((a,b)=>colliderReferenceScore(b,referenceBounds)-colliderReferenceScore(a,referenceBounds));
  return candidates[0];
}

function buildCombinedMesh(objects,mapPoint,colliderBase=null,proxyScan=null,coordinateFrame=null) {
  const vertices=[],indices=[],uvs=[],objectRanges=[];
  let removedMarkerObjects=0,removedMarkerFaces=0;
  let removedProxyObjects=0,removedProxyFaces=0;
  let removedColliderGeometryObjects=0,removedColliderGeometryFaces=0;
  let removedCoordinateFrameObjects=0,removedCoordinateFrameFaces=0;
  const removedMarkerNames=new Set();

  const poseIndependentColliderBoxes=new Set();
  for(const obj of objects){
    if(!obj?.vertices?.length||!obj?.faces?.length)continue;
    if(proxyScan?.proxyObjects?.has(obj))continue;
    if(coordinateFrame?.object===obj && coordinateFrame.exactFaceCount)continue;
    if(canonicalLegacyMarkerName(obj.name)||parseProxyObjectToken(obj.name))continue;
    if(matchesColliderBoxShapeIgnoringPose(obj,mapPoint,colliderBase))poseIndependentColliderBoxes.add(obj);
  }

  const hasNonBoxGeometry=objects.some(obj=>{
    if(!obj?.vertices?.length||!obj?.faces?.length)return false;
    if(proxyScan?.proxyObjects?.has(obj))return false;
    if(coordinateFrame?.object===obj && coordinateFrame.exactFaceCount)return false;
    if(canonicalLegacyMarkerName(obj.name)||parseProxyObjectToken(obj.name))return false;
    if(isReservedColliderGeometryName(obj.name))return false;
    return !poseIndependentColliderBoxes.has(obj);
  });

  for(const obj of objects){
    const oldObjectMarker=canonicalLegacyMarkerName(obj.name);
    if(oldObjectMarker){removedMarkerObjects++;removedMarkerNames.add(oldObjectMarker);continue;}

    const proxyObjectToken=parseProxyObjectToken(obj.name);
    if(!obj.vertices.length||!obj.faces.length)continue;

    if(coordinateFrame?.object===obj && coordinateFrame.exactFaceCount){
      removedCoordinateFrameObjects++;
      removedCoordinateFrameFaces+=obj.faces.length;
      continue;
    }

    // The exact uploaded converter welds the 36 UV-tagged proxy vertices into
    // eight shared cube corners and renames the object to Scene_2. The UV
    // averages still identify it deterministically, so remove the whole object.
    if(proxyScan?.proxyObjects?.has(obj)){
      removedProxyObjects++;
      removedProxyFaces+=obj.faces.length;
      continue;
    }

    // A dedicated proxy object is never Geometry, even if conversion damaged its UVs.
    if(proxyObjectToken){removedProxyObjects++;removedProxyFaces+=obj.faces.length;continue;}

    // The authored Collider root is metadata, never visible model Geometry.
    // Some FBX-to-3DS converters preserve that helper cube as an ordinary mesh.
    // Remove it by the reserved role name or by an exact corner match against
    // the UV proxy-derived BoxCollider.
    const isPoseIndependentColliderBox=
      poseIndependentColliderBoxes.has(obj)&&
      hasNonBoxGeometry&&
      (!objectHasMaterialAssignments(obj)||looksLikeColliderHelperName(obj.name));

    if(isReservedColliderGeometryName(obj.name)||
       matchesExactColliderGeometry(obj,mapPoint,colliderBase)||
       isPoseIndependentColliderBox){
      removedColliderGeometryObjects++;
      removedColliderGeometryFaces+=obj.faces.length;
      continue;
    }

    const geometryFaces=[];
    for(let fi=0;fi<obj.faces.length;fi++){
      if(coordinateFrame?.object===obj && coordinateFrame.faceIndices?.has(fi)){removedCoordinateFrameFaces++;continue;}
      const proxyFace=decodeProxyUvFace(obj,fi);
      if(proxyFace){removedProxyFaces++;continue;}
      const oldMaterialMarker=canonicalLegacyMarkerName(obj.faceMaterials?.[fi]);
      if(oldMaterialMarker){removedMarkerFaces++;removedMarkerNames.add(oldMaterialMarker);continue;}
      const face=obj.faces[fi];
      if(face.every(i=>i>=0&&i<obj.vertices.length))geometryFaces.push(face);
    }

    if(!geometryFaces.length)continue;

    const used=new Set();
    for(const face of geometryFaces)for(const i of face)used.add(i);
    const sorted=[...used].sort((a,b)=>a-b);
    const remap=new Map();
    const base=vertices.length/3,indexStart=indices.length;

    for(const oldIndex of sorted){
      const newIndex=vertices.length/3;
      remap.set(oldIndex,newIndex);
      // 3DS MESH_MATRIX is an object coordinate-system descriptor for the
      // converters used by this pipeline. Applying it again to visible Geometry
      // rotates/translates the model a second time. Proxy parsing still consumes
      // the matrix because its pivot is intentionally stored there.
      const v=mapPoint(obj.vertices[oldIndex]);
      vertices.push(v[0],v[1],v[2]);
      const uv=obj.uvs.length===obj.vertices.length?obj.uvs[oldIndex]:[0,0];
      uvs.push(uv[0],uv[1]);
    }
    for(const face of geometryFaces)indices.push(remap.get(face[0]),remap.get(face[1]),remap.get(face[2]));
    objectRanges.push({name:obj.name,vertexStart:base,vertexCount:sorted.length,indexStart,indexCount:indices.length-indexStart});
  }

  if(!vertices.length)throw new Error('The 3DS contains no model Geometry after removal of the dedicated collider proxy.');
  if(!indices.length)throw new Error('The 3DS contains no model triangle faces after collider-proxy removal.');

  const normals=new Float32Array(vertices.length);
  for(let i=0;i<indices.length;i+=3){
    const ia=indices[i]*3,ib=indices[i+1]*3,ic=indices[i+2]*3;
    const ax=vertices[ia],ay=vertices[ia+1],az=vertices[ia+2],bx=vertices[ib],by=vertices[ib+1],bz=vertices[ib+2],cx=vertices[ic],cy=vertices[ic+1],cz=vertices[ic+2];
    const ux=bx-ax,uy=by-ay,uz=bz-az,vx=cx-ax,vy=cy-ay,vz=cz-az;
    const nx=uy*vz-uz*vy,ny=uz*vx-ux*vz,nz=ux*vy-uy*vx;
    normals[ia]+=nx;normals[ia+1]+=ny;normals[ia+2]+=nz;normals[ib]+=nx;normals[ib+1]+=ny;normals[ib+2]+=nz;normals[ic]+=nx;normals[ic+1]+=ny;normals[ic+2]+=nz;
  }
  for(let i=0;i<normals.length;i+=3){const l=Math.hypot(normals[i],normals[i+1],normals[i+2])||1;normals[i]/=l;normals[i+1]/=l;normals[i+2]/=l;}
  const min=[Infinity,Infinity,Infinity],max=[-Infinity,-Infinity,-Infinity];
  for(let i=0;i<vertices.length;i+=3)for(let a=0;a<3;a++){min[a]=Math.min(min[a],vertices[i+a]);max[a]=Math.max(max[a],vertices[i+a]);}
  return {
    vertices:new Float32Array(vertices),indices:new Uint32Array(indices),normals,uvs:new Float32Array(uvs),min,max,objectRanges,
    removedMarkerObjects,removedMarkerFaces,removedMarkerNames:[...removedMarkerNames].sort(),
    removedProxyObjects,removedProxyFaces,
    removedColliderGeometryObjects,removedColliderGeometryFaces,
    removedCoordinateFrameObjects,removedCoordinateFrameFaces
  };
}

export function parse3DS(input) {
  const bytes=input instanceof Uint8Array?input:new Uint8Array(input);
  if(bytes.length<6)throw new Error('File is too small to be a 3DS model.');
  const view=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
  const root=readChunk(view,0,bytes.length);
  if(![CH.M3D_MAGIC,CH.MLIB_MAGIC,CH.C_MAGIC].includes(root.id))throw new Error('Not a supported 3DS file.');

  const objects=[];
  let masterScale=1;

  function walk(off,limit){
    while(off<limit){
      const c=readChunk(view,off,limit);
      if(c.id===CH.MDATA)walk(c.data,c.end);
      else if(c.id===CH.MASTER_SCALE&&c.data+4<=c.end){const s=view.getFloat32(c.data,true);if(Number.isFinite(s)&&s>0&&s<1e9)masterScale*=s;}
      else if(c.id===CH.NAMED_OBJECT){const name=readCString(bytes,c.data,c.end);walkNamed(name.next,c.end,name.text||`Object_${objects.length+1}`);}
      off=c.end;
    }
  }

  function walkNamed(off,limit,name){while(off<limit){const c=readChunk(view,off,limit);if(c.id===CH.N_TRI_OBJECT)parseTriObject(c.data,c.end,name);off=c.end;}}

  function parseTriObject(off,limit,name){
    let localVerts=[],faces=[],uv=[],meshMatrix=null,faceMaterials=[];
    while(off<limit){
      const c=readChunk(view,off,limit);
      if(c.id===CH.POINT_ARRAY){
        if(c.data+2>c.end)throw new Error('Truncated 3DS vertex array.');
        const n=view.getUint16(c.data,true);let p=c.data+2;if(p+n*12>c.end)throw new Error('Invalid 3DS vertex count.');
        localVerts=new Array(n);for(let i=0;i<n;i++){localVerts[i]=[view.getFloat32(p,true),view.getFloat32(p+4,true),view.getFloat32(p+8,true)];p+=12;}
      }else if(c.id===CH.FACE_ARRAY){
        if(c.data+2>c.end)throw new Error('Truncated 3DS face array.');
        const n=view.getUint16(c.data,true);let p=c.data+2;if(p+n*8>c.end)throw new Error('Invalid 3DS face count.');
        faces=[];faceMaterials=new Array(n).fill('');
        for(let i=0;i<n;i++){faces.push([view.getUint16(p,true),view.getUint16(p+2,true),view.getUint16(p+4,true)]);p+=8;}
        while(p<c.end){
          const sub=readChunk(view,p,c.end);
          if(sub.id===CH.MSH_MAT_GROUP){
            const material=readCString(bytes,sub.data,sub.end);
            if(material.next+2>sub.end)throw new Error(`Truncated 3DS material group in ${name}.`);
            const count=view.getUint16(material.next,true);let q=material.next+2;
            if(q+count*2>sub.end)throw new Error(`Invalid 3DS material face list in ${name}.`);
            for(let i=0;i<count;i++){const faceIndex=view.getUint16(q,true);q+=2;if(faceIndex<n)faceMaterials[faceIndex]=material.text;}
          }
          p=sub.end;
        }
      }else if(c.id===CH.TEX_VERTS&&c.data+2<=c.end){
        const n=view.getUint16(c.data,true);let p=c.data+2;if(p+n*8<=c.end){uv=new Array(n);for(let i=0;i<n;i++){uv[i]=[view.getFloat32(p,true),view.getFloat32(p+4,true)];p+=8;}}
      }else if(c.id===CH.MESH_MATRIX){
        if(c.data+48>c.end)throw new Error(`Truncated 3DS mesh matrix for ${name}.`);
        meshMatrix=new Array(12);for(let i=0;i<12;i++)meshMatrix[i]=view.getFloat32(c.data+i*4,true);
      }
      off=c.end;
    }
    if(localVerts.length)objects.push({name,vertices:localVerts,faces,uvs:uv,faceMaterials,meshMatrix});
  }

  walk(root.data,root.end);
  if(!objects.length)throw new Error('3DS contains no triangle-mesh objects.');
  if(masterScale!==1)for(const obj of objects)for(const v of obj.vertices){v[0]*=masterScale;v[1]*=masterScale;v[2]*=masterScale;}

  const coordinateFrame=findGeometricCoordinateFrame(objects);
  let proxyScan=scanColliderProxy(objects);
  const legacyScan=scanLegacyMarkers(objects);
  const hasLegacyCalibration=[LEGACY.ORIGIN,LEGACY.AXIS_X,LEGACY.AXIS_Y,LEGACY.AXIS_Z].some(name=>!!findLegacyNamed(legacyScan.markers,name));

  let coordinateObjects=objects;
  let coordinateLegacyMarkers=legacyScan.markers;
  let legacyCalibration=null;
  let matrixFallbackUsed=false;

  if(!coordinateFrame&&hasLegacyCalibration){
    try{
      legacyCalibration=parseLegacyCalibration(legacyScan.markers);
    }catch(rawError){
      const matrixObjects=objects.map(cloneObjectWithMatrixApplied);
      const matrixLegacy=legacyScan.markers.map(cloneObjectWithMatrixApplied);
      try{
        legacyCalibration=parseLegacyCalibration(matrixLegacy);
        coordinateObjects=matrixObjects;
        coordinateLegacyMarkers=matrixLegacy;
        matrixFallbackUsed=true;
      }catch(matrixError){
        throw new Error(`${rawError.message} Matrix fallback also failed: ${matrixError.message}`);
      }
    }
  }

  const weldedCoordinateMap=
    !coordinateFrame&&!legacyCalibration&&proxyScan?.weldedProxy
      ? createWeldedProxyCoordinateMap(proxyScan.weldedProxy)
      : null;

  const mapPoint=coordinateFrame
    ? p=>transformByInverseBasis(p,coordinateFrame.origin,coordinateFrame.inverse)
    : legacyCalibration
      ? p=>transformByInverseBasis(p,legacyCalibration.origin,legacyCalibration.inverse)
      : weldedCoordinateMap
        ? weldedCoordinateMap
        : p=>legacyToEditor(p[0],p[1],p[2]);

  if(!proxyScan)proxyScan=findEndpointColliderProxy(objects,mapPoint);

  let colliderBase=null;
  let sourceToken='';
  let sourceCalibrated=false;
  let calibrationMode='none';

  if(proxyScan){
    colliderBase=parseExactColliderProxy(proxyScan,mapPoint,objects);
    sourceToken=proxyScan.token;
    sourceCalibrated=!!coordinateFrame||!!legacyCalibration;
    const proxyMode=proxyScan.endpointFallback
      ?'exact-collider-proxy-endpoints'
      :proxyScan.geometryFallback
        ?'exact-collider-proxy-geometry'
        :'exact-collider-proxy';
    calibrationMode=coordinateFrame
      ?`coordinate-frame+${proxyMode}`
      :legacyCalibration
        ?`legacy-markers+${proxyMode}`
        :`uncalibrated-${proxyMode}`;
  }else{
    colliderBase=parseLegacyCollider(coordinateLegacyMarkers,mapPoint);
    sourceToken=parseLegacyIdentityToken(coordinateLegacyMarkers);
    sourceCalibrated=!!legacyCalibration&&!!colliderBase;
    calibrationMode=legacyCalibration?'legacy-markers':'none';
  }

  const recoveredProxyCollider=colliderBase;
  const combined=buildCombinedMesh(
    coordinateObjects,
    mapPoint,
    recoveredProxyCollider,
    proxyScan,
    coordinateFrame
  );

  // A saveable source uses the REAL collider proxy recovered in the same
  // calibrated Shared Patch Root coordinate system as Geometry.  Never replace
  // it with Geometry AABB extents: doing so loses collider orientation/pivot and
  // can turn centimeter-converted 3DS values into enormous Unity colliders.
  const geometrySize=combined.max.map((v,i)=>Math.max(1e-4,v-combined.min[i]));
  const geometryCenter=combined.min.map((v,i)=>(v+combined.max[i])*0.5);
  const displayColliderBase=sourceCalibrated&&recoveredProxyCollider
    ?recoveredProxyCollider
    :{
      center:geometryCenter,
      size:geometrySize,
      rotation:[0,0,0,1],
      fromGeometryBounds:true,
      uncalibratedDisplayOnly:true
    };

  combined.colliderBase=displayColliderBase;
  combined.sourceToken=sourceToken;
  combined.calibrated=sourceCalibrated;
  combined.meshMatrixFallbackUsed=matrixFallbackUsed;
  combined.raw=bytes.slice();
  combined.diagnostics={
    sourceObjectCount:objects.length,
    geometryObjectCount:combined.objectRanges.length,
    vertexCount:combined.vertices.length/3,
    triangleCount:combined.indices.length/3,
    markerObjectsByName:legacyScan.markerObjectsByName,
    markerMaterialGroups:legacyScan.markerMaterialGroups,
    removedMarkerObjects:combined.removedMarkerObjects,
    removedMarkerFaces:combined.removedMarkerFaces,
    removedProxyObjects:combined.removedProxyObjects,
    removedProxyFaces:combined.removedProxyFaces,
    removedColliderGeometryObjects:combined.removedColliderGeometryObjects,
    removedColliderGeometryFaces:combined.removedColliderGeometryFaces,
    proxyTaggedFaces:proxyScan?.proxyFaceCount||0,
    proxyToken:proxyScan?.token||'',
    calibrationMode,
    coordinateFrameRecovered:!!coordinateFrame,
    coordinateFrameObjectName:coordinateFrame?.object?.name||'',
    coordinateFrameMaximumError:coordinateFrame?.maximumError??null,
    removedCoordinateFrameObjects:combined.removedCoordinateFrameObjects||0,
    removedCoordinateFrameFaces:combined.removedCoordinateFrameFaces||0,
    sourceObjectNames:objects.map(o=>o.name),
    matrixFallbackUsed,
    weldedProxyRecovered:!!proxyScan?.weldedProxy,
    colliderSource:sourceCalibrated&&recoveredProxyCollider?'calibrated-proxy-box':'geometry-extents-display-only',
    proxyColliderSource:proxyScan?.endpointFallback
      ?'recovered-endpoint-box'
      :proxyScan
        ?'recovered-proxy-mesh'
        :'none',
    endpointProxyRecovered:!!proxyScan?.endpointFallback,
    partialUvProxyRecovered:!!proxyScan?.partialUvFallback
  };
  return combined;
}
