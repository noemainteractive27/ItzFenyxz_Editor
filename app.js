import { parse3DS, encodeITZF, decodeITZF, identityTransform, cloneTransform, sanitizeObjectID } from './core.js?v=0.9.2e-embedded-calibration-1';

const $ = (id) => document.getElementById(id);
const canvas = $('viewport');
const viewportShell = $('viewportShell');
const hierarchy = $('hierarchy');
const fileInput = $('fileInput');
const openBtn = $('openBtn'), saveBtn = $('saveBtn'), saveAsBtn = $('saveAsBtn');
const moveBtn = $('moveBtn'), rotateBtn = $('rotateBtn'), scaleBtn = $('scaleBtn'), spaceBtn = $('spaceBtn');
const axisButtons = [...document.querySelectorAll('.axis-button')], transformSpeed = $('transformSpeed'), helpBtn = $('helpBtn'), installBtn = $('installBtn');
const frontBtn = $('frontBtn'), rightBtn = $('rightBtn'), topBtn = $('topBtn'), frameBtn = $('frameBtn');
const geometryLayer = $('geometryLayer'), colliderLayer = $('colliderLayer'), gridLayer = $('gridLayer');
const resetTransformBtn = $('resetTransformBtn'), showCollidersBtn = $('showCollidersBtn');
const objectIdValue = $('objectIdValue'), sourceValue = $('sourceValue'), selectedValue = $('selectedValue');
const colliderStateValue = $('colliderStateValue'), colliderSizeValue = $('colliderSizeValue');
const geometryObjectsValue = $('geometryObjectsValue'), geometryVerticesValue = $('geometryVerticesValue');
const geometryTrianglesValue = $('geometryTrianglesValue'), markerCountValue = $('markerCountValue');
const colliderProxyValue = $('colliderProxyValue');
const calibrationValue = $('calibrationValue'), matrixRecoveryValue = $('matrixRecoveryValue');
const sourceWarning = $('sourceWarning');
const fileIndicator = $('fileIndicator'), statusText = $('statusText'), historyStatus = $('historyStatus'), dirtyStatus = $('dirtyStatus');
const emptyViewport = $('emptyViewport'), viewportBadge = $('viewportBadge'), transformHint = $('transformHint');
const toastEl = $('toast'), fatalBanner = $('fatalBanner');
const inspectorInputs = [...document.querySelectorAll('.vector-group input')];

let toastTimer = 0;
let lastErrorSignature = '', lastErrorAt = 0;
function toast(msg) { toastEl.textContent = msg; toastEl.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => toastEl.classList.remove('show'), 1500); }
function setStatus(msg) { statusText.textContent = msg; }
function reportError(error, context = 'runtime') {
  const message = error instanceof Error ? `${error.message}\n${error.stack || ''}` : String(error);
  const signature = `${context}:${message.split('\n')[0]}`, now = performance.now();
  if (signature === lastErrorSignature && now - lastErrorAt < 2500) return;
  lastErrorSignature = signature; lastErrorAt = now;
  console.error(context, error);
  fatalBanner.textContent = `${context}: ${message.split('\n')[0]}`;
  fatalBanner.classList.remove('hidden');
  try {
    const previous = localStorage.getItem('itzfenyxz-error-log') || '';
    const entry = `[${new Date().toISOString()}] ${context}
${message}

`;
    localStorage.setItem('itzfenyxz-error-log', (previous + entry).slice(-50000));
  } catch {}
}
window.addEventListener('error', e => reportError(e.error || e.message, 'JavaScript error'));
window.addEventListener('unhandledrejection', e => reportError(e.reason, 'Unhandled promise rejection'));

// ---------- small math layer ----------
const V3 = {
  add: (a,b) => [a[0]+b[0],a[1]+b[1],a[2]+b[2]],
  sub: (a,b) => [a[0]-b[0],a[1]-b[1],a[2]-b[2]],
  mul: (a,s) => [a[0]*s,a[1]*s,a[2]*s],
  dot: (a,b) => a[0]*b[0]+a[1]*b[1]+a[2]*b[2],
  cross: (a,b) => [a[1]*b[2]-a[2]*b[1],a[2]*b[0]-a[0]*b[2],a[0]*b[1]-a[1]*b[0]],
  len: a => Math.hypot(a[0],a[1],a[2]),
  norm: a => { const l=Math.hypot(a[0],a[1],a[2])||1; return [a[0]/l,a[1]/l,a[2]/l]; }
};
function qNorm(q){const l=Math.hypot(...q)||1;return q.map(v=>v/l);}
function qMul(a,b){return qNorm([
  a[3]*b[0]+a[0]*b[3]+a[1]*b[2]-a[2]*b[1],
  a[3]*b[1]-a[0]*b[2]+a[1]*b[3]+a[2]*b[0],
  a[3]*b[2]+a[0]*b[1]-a[1]*b[0]+a[2]*b[3],
  a[3]*b[3]-a[0]*b[0]-a[1]*b[1]-a[2]*b[2]
]);}
function qAxis(axis,angle){const s=Math.sin(angle/2);return qNorm([axis[0]*s,axis[1]*s,axis[2]*s,Math.cos(angle/2)]);}
function qFromEulerDeg(e){
  const x=e[0]*Math.PI/180,y=e[1]*Math.PI/180,z=e[2]*Math.PI/180;
  const cx=Math.cos(x/2),sx=Math.sin(x/2),cy=Math.cos(y/2),sy=Math.sin(y/2),cz=Math.cos(z/2),sz=Math.sin(z/2);
  return qNorm([sx*cy*cz+cx*sy*sz, cx*sy*cz-sx*cy*sz, cx*cy*sz+sx*sy*cz, cx*cy*cz-sx*sy*sz]);
}
function eulerDegFromQ(q){
  q=qNorm(q); const [x,y,z,w]=q;
  const sinr=2*(w*x-y*z), cosr=1-2*(x*x+y*y);
  const rx=Math.atan2(sinr,cosr);
  const sinp=2*(w*y+z*x); const ry=Math.abs(sinp)>=1?Math.sign(sinp)*Math.PI/2:Math.asin(sinp);
  const siny=2*(w*z-x*y), cosy=1-2*(y*y+z*z); const rz=Math.atan2(siny,cosy);
  return [rx,ry,rz].map(v=>v*180/Math.PI);
}
function m4Identity(){return new Float32Array([1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1]);}
function m4Mul(a,b){const o=new Float32Array(16);for(let c=0;c<4;c++)for(let r=0;r<4;r++){let s=0;for(let k=0;k<4;k++)s+=a[k*4+r]*b[c*4+k];o[c*4+r]=s;}return o;}
function m4FromTRS(t){
  const [x,y,z,w]=qNorm(t.rotation), [sx,sy,sz]=t.scale, [px,py,pz]=t.position;
  const xx=x*x,yy=y*y,zz=z*z,xy=x*y,xz=x*z,yz=y*z,wx=w*x,wy=w*y,wz=w*z;
  return new Float32Array([
    (1-2*(yy+zz))*sx,(2*(xy+wz))*sx,(2*(xz-wy))*sx,0,
    (2*(xy-wz))*sy,(1-2*(xx+zz))*sy,(2*(yz+wx))*sy,0,
    (2*(xz+wy))*sz,(2*(yz-wx))*sz,(1-2*(xx+yy))*sz,0,
    px,py,pz,1
  ]);
}
function m4Perspective(fov,aspect,near,far){const f=1/Math.tan(fov/2),nf=1/(near-far);return new Float32Array([f/aspect,0,0,0,0,f,0,0,0,0,(far+near)*nf,-1,0,0,2*far*near*nf,0]);}
function m4LookAt(eye,target,up0=[0,1,0]){
  const f=V3.norm(V3.sub(target,eye)); let s=V3.norm(V3.cross(f,up0)); if(V3.len(s)<1e-8)s=[1,0,0]; const u=V3.cross(s,f);
  return new Float32Array([s[0],u[0],-f[0],0,s[1],u[1],-f[1],0,s[2],u[2],-f[2],0,-V3.dot(s,eye),-V3.dot(u,eye),V3.dot(f,eye),1]);
}
function transformPoint(m,p){return [m[0]*p[0]+m[4]*p[1]+m[8]*p[2]+m[12],m[1]*p[0]+m[5]*p[1]+m[9]*p[2]+m[13],m[2]*p[0]+m[6]*p[1]+m[10]*p[2]+m[14]];}
function compose(a,b){return m4Mul(m4FromTRS(a),m4FromTRS(b));}
function fmt(n){return Math.abs(n)<1e-9?'0':Number(n.toFixed(4)).toString();}
function cloneState(s){return JSON.parse(JSON.stringify(s));}

// ---------- model state ----------
let model = null;
let selectedKey = null;
let history = [], redoStack = [];
let savedState = '';
let dirty = false;
let saveHandle = null;
let localSpace = false;
let showGeometry = true, showColliders = false, showGrid = true;
let activeTool = null;
let axisConstraint = null;
let transformDrag = null;
let lastPointer = {x:0,y:0};

function stateSnapshot(){
  if(!model)return null;
  return { root:cloneTransform(model.root), visual:cloneTransform(model.visual), collider:cloneTransform(model.collider), visualPresent:model.visualPresent, colliderPresent:model.colliderPresent };
}
function applySnapshot(s){ if(!model||!s)return; model.root=cloneTransform(s.root); model.visual=cloneTransform(s.visual); model.collider=cloneTransform(s.collider); model.visualPresent=!!s.visualPresent; model.colliderPresent=!!s.colliderPresent; refreshAll(); }
function persistentState(){return model?JSON.stringify(stateSnapshot()):'';}
function setDirty(){dirty=!!model&&persistentState()!==savedState;dirtyStatus.textContent=dirty?'Modified':'Saved';dirtyStatus.classList.toggle('dirty',dirty);document.title=`${dirty?'● ':''}ITZFENYXZ Editor${model?` — ${model.objectId}`:''}`;}
function pushUndo(before){if(!before)return; history.push(before); if(history.length>100)history.shift(); redoStack=[]; updateHistory();}
function undo(){if(!model||!history.length)return;const cur=stateSnapshot();const s=history.pop();redoStack.push(cur);applySnapshot(s);setDirty();updateHistory();setStatus('Undo');}
function redo(){if(!model||!redoStack.length)return;const cur=stateSnapshot();const s=redoStack.pop();history.push(cur);applySnapshot(s);setDirty();updateHistory();setStatus('Redo');}
function updateHistory(){historyStatus.textContent=`Undo ${history.length} / Redo ${redoStack.length}`;}
function selectedTransform(){if(!model)return null;return selectedKey==='root'?model.root:selectedKey==='visual'?model.visual:selectedKey==='collider'?model.collider:null;}
function selectedPresent(){return !!model && (selectedKey==='root'?(model.visualPresent||model.colliderPresent):selectedKey==='visual'?model.visualPresent:selectedKey==='collider'?model.colliderPresent:false);}

function matrixBasisIsExactBox(m){
  const x=[m[0],m[1],m[2]],y=[m[4],m[5],m[6]],z=[m[8],m[9],m[10]];
  const lx=V3.len(x),ly=V3.len(y),lz=V3.len(z);
  if(!Number.isFinite(lx)||!Number.isFinite(ly)||!Number.isFinite(lz)||Math.min(lx,ly,lz)<1e-7)return false;
  const nx=V3.mul(x,1/lx),ny=V3.mul(y,1/ly),nz=V3.mul(z,1/lz);
  const shear=Math.max(Math.abs(V3.dot(nx,ny)),Math.abs(V3.dot(nx,nz)),Math.abs(V3.dot(ny,nz)));
  if(shear>0.001)return false;
  return V3.dot(V3.cross(ny,nz),nx)>=0.999;
}
function positiveScale(t){return t.scale.every(v=>Number.isFinite(v)&&v>1e-7);}
function sourceIsSaveable(){return !!model&&model.sourceCalibrated;}
function validateModelForSave(){
  if(!model)throw new Error('No model is loaded.');
  if(!model.sourceCalibrated)throw new Error('ITZ-E1201: Source calibration data is missing or invalid.');
  // A 3DS converter may destroy the ICxxxxx object name / UV token while the
  // calibrated proxy geometry still survives. Unity can safely identify the
  // patch by ObjectId when the token is absent, so saving must not be blocked.
  if(model.colliderPresent){
    if(!positiveScale(model.root)||!positiveScale(model.collider))throw new Error('Root and Box Collider scales must stay positive while the collider exists. Delete the collider first if a mirrored transform is intentional.');
    const base={position:model.colliderBaseCenter,rotation:model.colliderBaseRotation,scale:model.colliderBaseSize};
    const matrix=m4Mul(m4Mul(m4FromTRS(model.root),m4FromTRS(model.collider)),m4FromTRS(base));
    if(!matrixBasisIsExactBox(matrix))throw new Error('This Root/Collider transform would create a sheared or mirrored box that Unity cannot reproduce exactly. Adjust rotation/scale or delete the collider.');
  }
}

function manifestFromModel(){return {
  objectId:model.objectId,
  sourceName:model.sourceName,
  sourceFormat:'3ds',
  source:{name:model.sourceName,format:'3ds',token:model.sourceToken||'',calibrated:!!model.sourceCalibrated},
  root:cloneTransform(model.root),
  visual:{present:model.visualPresent,transform:cloneTransform(model.visual)},
  collider:{apply:true,present:model.colliderPresent,type:'box',baseCenter:[...model.colliderBaseCenter],baseSize:[...model.colliderBaseSize],baseRotation:[...model.colliderBaseRotation],transform:cloneTransform(model.collider)}
};}

// ---------- WebGL ----------
const gl = canvas.getContext('webgl', { antialias:true, alpha:false, depth:true, preserveDrawingBuffer:false, powerPreference:'high-performance' });
if(!gl) throw new Error('WebGL is unavailable. Update the graphics driver or enable hardware acceleration in the browser.');
canvas.addEventListener('webglcontextlost',e=>{e.preventDefault();reportError('The graphics context was lost. Close and reopen the editor.', 'WebGL');});
canvas.addEventListener('contextmenu',e=>e.preventDefault());

function shader(type,src){const s=gl.createShader(type);gl.shaderSource(s,src);gl.compileShader(s);if(!gl.getShaderParameter(s,gl.COMPILE_STATUS))throw new Error(gl.getShaderInfoLog(s)||'Shader compile failed');return s;}
function program(vs,fs){const p=gl.createProgram();gl.attachShader(p,shader(gl.VERTEX_SHADER,vs));gl.attachShader(p,shader(gl.FRAGMENT_SHADER,fs));gl.linkProgram(p);if(!gl.getProgramParameter(p,gl.LINK_STATUS))throw new Error(gl.getProgramInfoLog(p)||'Program link failed');return p;}
const meshProgram=program(`
attribute vec3 aPos; attribute vec3 aNormal; uniform mat4 uMVP; uniform mat4 uModel; varying vec3 vN;
void main(){ gl_Position=uMVP*vec4(aPos,1.0); vN=normalize(mat3(uModel)*aNormal); }
`,`precision mediump float; varying vec3 vN; uniform vec3 uColor; void main(){ vec3 n=normalize(vN); float d=max(dot(n,normalize(vec3(.45,.9,.55))),0.0); float l=.34+.66*d; gl_FragColor=vec4(uColor*l,1.0); }`);
const lineProgram=program(`attribute vec3 aPos; uniform mat4 uMVP; void main(){gl_Position=uMVP*vec4(aPos,1.0);}`,`precision mediump float; uniform vec4 uColor; void main(){gl_FragColor=uColor;}`);
const meshLoc={pos:gl.getAttribLocation(meshProgram,'aPos'),normal:gl.getAttribLocation(meshProgram,'aNormal'),mvp:gl.getUniformLocation(meshProgram,'uMVP'),model:gl.getUniformLocation(meshProgram,'uModel'),color:gl.getUniformLocation(meshProgram,'uColor')};
const lineLoc={pos:gl.getAttribLocation(lineProgram,'aPos'),mvp:gl.getUniformLocation(lineProgram,'uMVP'),color:gl.getUniformLocation(lineProgram,'uColor')};
const meshPosBuf=gl.createBuffer(),
  meshNormBuf=gl.createBuffer(),
  meshWireBuf=gl.createBuffer(),
  lineBuf=gl.createBuffer();

let meshVertexCount=0;
let meshWireVertexCount=0;

function uploadMesh(mesh){
  const triCount=mesh.indices.length/3;
  if(triCount>2_000_000)throw new Error(`Model has ${Math.round(triCount).toLocaleString()} triangles; the editor limit is 2,000,000.`);

  const pos=new Float32Array(mesh.indices.length*3);
  const nor=new Float32Array(mesh.indices.length*3);
  const wire=new Float32Array(triCount*6*3);

  for(let i=0;i<mesh.indices.length;i++){
    const si=mesh.indices[i]*3,di=i*3;
    pos[di]=mesh.vertices[si];
    pos[di+1]=mesh.vertices[si+1];
    pos[di+2]=mesh.vertices[si+2];
    nor[di]=mesh.normals[si];
    nor[di+1]=mesh.normals[si+1];
    nor[di+2]=mesh.normals[si+2];
  }

  let wi=0;
  for(let i=0;i<mesh.indices.length;i+=3){
    const a=mesh.indices[i],b=mesh.indices[i+1],c=mesh.indices[i+2];
    for(const index of [a,b,b,c,c,a]){
      const source=index*3;
      wire[wi++]=mesh.vertices[source];
      wire[wi++]=mesh.vertices[source+1];
      wire[wi++]=mesh.vertices[source+2];
    }
  }

  gl.bindBuffer(gl.ARRAY_BUFFER,meshPosBuf);
  gl.bufferData(gl.ARRAY_BUFFER,pos,gl.STATIC_DRAW);

  gl.bindBuffer(gl.ARRAY_BUFFER,meshNormBuf);
  gl.bufferData(gl.ARRAY_BUFFER,nor,gl.STATIC_DRAW);

  gl.bindBuffer(gl.ARRAY_BUFFER,meshWireBuf);
  gl.bufferData(gl.ARRAY_BUFFER,wire,gl.STATIC_DRAW);

  meshVertexCount=mesh.indices.length;
  meshWireVertexCount=wire.length/3;
}
function drawLines(points,color,mvp,mode=gl.LINES){
  if(!points.length)return; const arr=points instanceof Float32Array?points:new Float32Array(points);
  gl.useProgram(lineProgram);gl.bindBuffer(gl.ARRAY_BUFFER,lineBuf);gl.bufferData(gl.ARRAY_BUFFER,arr,gl.DYNAMIC_DRAW);gl.enableVertexAttribArray(lineLoc.pos);gl.vertexAttribPointer(lineLoc.pos,3,gl.FLOAT,false,0,0);gl.uniformMatrix4fv(lineLoc.mvp,false,mvp);gl.uniform4fv(lineLoc.color,color);gl.drawArrays(mode,0,arr.length/3);
}
function drawMesh(modelMat,vp){
  if(!meshVertexCount)return;gl.useProgram(meshProgram);gl.bindBuffer(gl.ARRAY_BUFFER,meshPosBuf);gl.enableVertexAttribArray(meshLoc.pos);gl.vertexAttribPointer(meshLoc.pos,3,gl.FLOAT,false,0,0);gl.bindBuffer(gl.ARRAY_BUFFER,meshNormBuf);gl.enableVertexAttribArray(meshLoc.normal);gl.vertexAttribPointer(meshLoc.normal,3,gl.FLOAT,false,0,0);gl.uniformMatrix4fv(meshLoc.model,false,modelMat);gl.uniformMatrix4fv(meshLoc.mvp,false,m4Mul(vp,modelMat));gl.uniform3f(meshLoc.color,.68,.70,.72);gl.drawArrays(gl.TRIANGLES,0,meshVertexCount);
}
function drawMeshWire(modelMat,vp,color){
  if(!meshWireVertexCount)return;

  gl.useProgram(lineProgram);
  gl.bindBuffer(gl.ARRAY_BUFFER,meshWireBuf);
  gl.enableVertexAttribArray(lineLoc.pos);
  gl.vertexAttribPointer(lineLoc.pos,3,gl.FLOAT,false,0,0);
  gl.uniformMatrix4fv(lineLoc.mvp,false,m4Mul(vp,modelMat));
  gl.uniform4fv(lineLoc.color,color);
  gl.drawArrays(gl.LINES,0,meshWireVertexCount);
}
function boxCorners(center,size,modelMat){const h=size.map(v=>v/2),out=[];for(let i=0;i<8;i++){const p=[center[0]+(i&1?h[0]:-h[0]),center[1]+(i&2?h[1]:-h[1]),center[2]+(i&4?h[2]:-h[2])];out.push(transformPoint(modelMat,p));}return out;}
const boxEdges=[[0,1],[1,3],[3,2],[2,0],[4,5],[5,7],[7,6],[6,4],[0,4],[1,5],[2,6],[3,7]];
const boxFaces=[[0,1,3],[0,3,2],[4,7,5],[4,6,7],[0,5,1],[0,4,5],[2,3,7],[2,7,6],[0,2,6],[0,6,4],[1,5,7],[1,7,3]];
function edgesToPoints(c){const p=[];for(const [a,b] of boxEdges)p.push(...c[a],...c[b]);return p;}
function facesToPoints(c){const p=[];for(const f of boxFaces)p.push(...c[f[0]],...c[f[1]],...c[f[2]]);return p;}

const camera={target:[0,0,0],yaw:.72,pitch:.42,distance:6,fov:52*Math.PI/180};
function cameraBasis(){const cp=Math.cos(camera.pitch),eye=V3.add(camera.target,[camera.distance*cp*Math.sin(camera.yaw),camera.distance*Math.sin(camera.pitch),camera.distance*cp*Math.cos(camera.yaw)]);const forward=V3.norm(V3.sub(camera.target,eye));let right=V3.norm(V3.cross(forward,[0,1,0]));if(V3.len(right)<1e-8)right=[1,0,0];const up=V3.cross(right,forward);return{eye,forward,right,up};}
function vpMatrix(){const b=cameraBasis(),aspect=Math.max(.001,canvas.clientWidth/Math.max(1,canvas.clientHeight)),near=Math.max(.001,camera.distance*.001),far=Math.max(1000,camera.distance*1000);return m4Mul(m4Perspective(camera.fov,aspect,near,far),m4LookAt(b.eye,camera.target));}
function meshWorldMat(){return model?compose(model.root,model.visual):m4Identity();}
function colliderWorldMat(){
  if(!model)return m4Identity();
  const base={position:model.colliderBaseCenter,rotation:model.colliderBaseRotation,scale:[1,1,1]};
  return m4Mul(m4Mul(m4FromTRS(model.root),m4FromTRS(model.collider)),m4FromTRS(base));
}

function baseWorldBox(key){
  if(!model)return null; let corners;
  if(key==='collider')corners=boxCorners([0,0,0],model.colliderBaseSize,colliderWorldMat());
  else {const center=model.mesh.min.map((v,i)=>(v+model.mesh.max[i])/2),size=model.mesh.min.map((v,i)=>model.mesh.max[i]-v);corners=boxCorners(center,size,meshWorldMat());}
  const min=[Infinity,Infinity,Infinity],max=[-Infinity,-Infinity,-Infinity];for(const p of corners)for(let i=0;i<3;i++){min[i]=Math.min(min[i],p[i]);max[i]=Math.max(max[i],p[i]);}return{min,max,corners};
}
function selectedWorldCenter(){const b=baseWorldBox(selectedKey==='collider'?'collider':'visual');return b?b.min.map((v,i)=>(v+b.max[i])/2):[0,0,0];}

function updateCanvasSize(){const dpr=Math.min(window.devicePixelRatio||1,2),w=Math.max(1,Math.floor(canvas.clientWidth*dpr)),h=Math.max(1,Math.floor(canvas.clientHeight*dpr));if(canvas.width!==w||canvas.height!==h){canvas.width=w;canvas.height=h;}gl.viewport(0,0,w,h);}
function render(){
  try{
    updateCanvasSize();gl.clearColor(.055,.065,.074,1);gl.clear(gl.COLOR_BUFFER_BIT|gl.DEPTH_BUFFER_BIT);gl.enable(gl.DEPTH_TEST);gl.depthFunc(gl.LEQUAL);const vp=vpMatrix();
    if(showGrid){const span=model?Math.max(10,Math.max(...model.colliderBaseSize)*3):10,step=span/10,p=[];for(let i=-10;i<=10;i++){const v=i*step;p.push(-span,0,v, span,0,v, v,0,-span, v,0,span);}drawLines(p,[.19,.22,.24,1],vp);}
    if(model&&showGeometry&&model.visualPresent)drawMesh(meshWorldMat(),vp);
    let colliderCorners=null;
    if(model&&(showColliders||selectedKey==='collider')&&model.colliderPresent){
      colliderCorners=boxCorners([0,0,0],model.colliderBaseSize,colliderWorldMat());
    }
    if(model&&selectedPresent()){
      if(selectedKey==='collider'){
        const colliderBox=baseWorldBox('collider');
        if(colliderBox)drawLines(edgesToPoints(colliderBox.corners),[.95,.77,.29,1],vp);
      }else if(model.visualPresent){
        // Geometry selection follows the real triangle mesh. It is never
        // represented by a fake rectangular AABB.
        gl.disable(gl.DEPTH_TEST);
        drawMeshWire(meshWorldMat(),vp,[.95,.77,.29,.95]);
        gl.enable(gl.DEPTH_TEST);
      }

      const center=selectedWorldCenter(),diag=model?Math.max(...model.colliderBaseSize):1,s=Math.max(.15,Math.min(3,diag*.35)),g=[...center,center[0]+s,center[1],center[2],...center,center[0],center[1]+s,center[2],...center,center[0],center[1],center[2]+s];
      drawLines(g.slice(0,6),[.95,.24,.23,1],vp);drawLines(g.slice(6,12),[.25,.9,.42,1],vp);drawLines(g.slice(12,18),[.28,.5,1,1],vp);
    }
    // Collider wireframe is a viewport gizmo: keep it visible through the model, like an editor overlay.
    if(colliderCorners){gl.disable(gl.DEPTH_TEST);drawLines(edgesToPoints(colliderCorners),[.22,1,.42,1],vp);gl.enable(gl.DEPTH_TEST);}
  }catch(e){reportError(e,'Render');}
  requestAnimationFrame(render);
}
requestAnimationFrame(render);

// ---------- camera + selection ----------
function fitCamera(){if(!model)return;const b=baseWorldBox('visual');const center=b.min.map((v,i)=>(v+b.max[i])/2),size=b.min.map((v,i)=>b.max[i]-v),diag=Math.max(.001,Math.hypot(...size));camera.target=center;camera.distance=Math.max(.1,diag/(2*Math.tan(camera.fov/2))*1.35);}
function rayFromPointer(x,y){const rect=canvas.getBoundingClientRect(),nx=((x-rect.left)/rect.width)*2-1,ny=1-((y-rect.top)/rect.height)*2,aspect=rect.width/Math.max(1,rect.height),b=cameraBasis(),t=Math.tan(camera.fov/2),dir=V3.norm(V3.add(b.forward,V3.add(V3.mul(b.right,nx*t*aspect),V3.mul(b.up,ny*t))));return{o:b.eye,d:dir};}
function rayAABB(ray,box){let tmin=-Infinity,tmax=Infinity;for(let i=0;i<3;i++){if(Math.abs(ray.d[i])<1e-9){if(ray.o[i]<box.min[i]||ray.o[i]>box.max[i])return null;continue;}let a=(box.min[i]-ray.o[i])/ray.d[i],b=(box.max[i]-ray.o[i])/ray.d[i];if(a>b)[a,b]=[b,a];tmin=Math.max(tmin,a);tmax=Math.min(tmax,b);if(tmin>tmax)return null;}return tmax>=Math.max(0,tmin)?Math.max(0,tmin):null;}
function pickAt(x,y){if(!model)return;const r=rayFromPointer(x,y);let best=null;if(showColliders&&model.colliderPresent){const t=rayAABB(r,baseWorldBox('collider'));if(t!==null)best={key:'collider',t};}if(showGeometry&&model.visualPresent){const t=rayAABB(r,baseWorldBox('visual'));if(t!==null&&(!best||t<best.t))best={key:'visual',t};}if(best)select(best.key);}
let cameraDrag=null;
function pointerOverSelected(x,y){
  if(!model||!selectedPresent())return false;
  const ray=rayFromPointer(x,y);
  const box=baseWorldBox(selectedKey==='collider'?'collider':'visual');
  return !!box && rayAABB(ray,box)!==null;
}
canvas.addEventListener('pointerdown',e=>{
  canvas.focus();lastPointer={x:e.clientX,y:e.clientY};
  if(e.button===2){
    if(transformDrag){cancelTransformDrag();e.preventDefault();return;}
    cameraDrag={x:e.clientX,y:e.clientY,pan:e.shiftKey};
    canvas.setPointerCapture(e.pointerId);e.preventDefault();return;
  }
  if(e.button!==0)return;
  if(activeTool&&model&&selectedPresent()){
    // A transform starts only while the left button is held. Merely moving the
    // mouse after selecting a tool never changes the object.
    beginTransformDrag(e);
    return;
  }
  pickAt(e.clientX,e.clientY);
});
canvas.addEventListener('pointermove',e=>{
  lastPointer={x:e.clientX,y:e.clientY};
  if(cameraDrag){
    const dx=e.clientX-cameraDrag.x,dy=e.clientY-cameraDrag.y;
    cameraDrag.x=e.clientX;cameraDrag.y=e.clientY;
    if(cameraDrag.pan){
      const b=cameraBasis(),sc=camera.distance*.0016;
      camera.target=V3.add(camera.target,V3.add(V3.mul(b.right,-dx*sc),V3.mul(b.up,dy*sc)));
    }else{
      camera.yaw-=dx*.007;
      camera.pitch=Math.max(-1.54,Math.min(1.54,camera.pitch+dy*.007));
    }
    return;
  }
  if(transformDrag)applyTransformDrag(e);
});
canvas.addEventListener('pointerup',e=>{
  if(e.button===2&&cameraDrag){cameraDrag=null;try{canvas.releasePointerCapture(e.pointerId);}catch{}return;}
  if(e.button===0&&transformDrag)confirmTransformDrag(e.pointerId);
});
canvas.addEventListener('pointercancel',e=>{
  if(transformDrag)cancelTransformDrag(e.pointerId);
  if(cameraDrag){cameraDrag=null;try{canvas.releasePointerCapture(e.pointerId);}catch{}}
});
canvas.addEventListener('wheel',e=>{e.preventDefault();camera.distance*=Math.exp(e.deltaY*.0011);camera.distance=Math.max(.02,Math.min(1e6,camera.distance));},{passive:false});

// ---------- transform operations ----------
function toolLabel(mode){return mode==='move'?'MOVE':mode==='rotate'?'ROTATE':'SCALE';}
function axisLabel(){return axisConstraint===null?(activeTool==='scale'?'UNIFORM':'FREE'):['X','Y','Z'][axisConstraint];}
function updateToolUI(){
  const map={move:moveBtn,rotate:rotateBtn,scale:scaleBtn};
  for(const [mode,button] of Object.entries(map))button.classList.toggle('active',activeTool===mode);
  for(const button of axisButtons){
    const raw=button.dataset.axis;
    const value=raw==='free'?null:Number(raw);
    button.classList.toggle('active',value===axisConstraint);
  }
  canvas.classList.toggle('tool-armed',!!activeTool&&!transformDrag);
  canvas.classList.toggle('transform-dragging',!!transformDrag);
  if(!activeTool){transformHint.classList.add('hidden');return;}
  transformHint.textContent=`${toolLabel(activeTool)} · ${axisLabel()}`;
  transformHint.classList.remove('hidden');
}
function setActiveTool(mode){
  if(!model||!selectedPresent())return;
  if(transformDrag)cancelTransformDrag();
  activeTool=activeTool===mode?null:mode;
  if(activeTool==='rotate'&&axisConstraint===null)axisConstraint=1;
  updateToolUI();
}
function setAxis(axis){
  axisConstraint=axis;
  updateToolUI();
}
function transformSensitivity(event){
  let value=Number(transformSpeed?.value||1);
  if(event.shiftKey)value*=.15;
  return value;
}
function snapped(value,step,event){return event.ctrlKey?Math.round(value/step)*step:value;}
function beginTransformDrag(e){
  const t=selectedTransform();
  if(!t||!activeTool)return;
  transformDrag={
    mode:activeTool,
    axis:axisConstraint,
    before:stateSnapshot(),
    start:cloneTransform(t),
    x:e.clientX,
    y:e.clientY,
    pointerId:e.pointerId
  };
  canvas.setPointerCapture(e.pointerId);
  updateToolUI();
  e.preventDefault();
}
function applyTransformDrag(e){
  const s=transformDrag,t=selectedTransform();if(!s||!t)return;
  const dx=e.clientX-s.x,dy=e.clientY-s.y;
  const sensitivity=transformSensitivity(e);
  if(s.mode==='move'){
    if(s.axis!==null){
      const raw=(dx-dy)*camera.distance*.0015*sensitivity;
      const delta=snapped(raw,.1,e);
      t.position=[...s.start.position];t.position[s.axis]+=delta;
    }else{
      const b=cameraBasis(),sc=camera.distance*.0015*sensitivity;
      let sx=dx*sc,sy=-dy*sc;
      if(e.ctrlKey){sx=snapped(sx,.1,e);sy=snapped(sy,.1,e);}
      t.position=V3.add(s.start.position,V3.add(V3.mul(b.right,sx),V3.mul(b.up,sy)));
    }
  }else if(s.mode==='scale'){
    let factor=Math.max(.001,Math.exp((dx-dy)*.006*sensitivity));
    if(e.ctrlKey)factor=Math.max(.001,Math.round(factor/.05)*.05);
    t.scale=[...s.start.scale];
    if(s.axis===null)t.scale=t.scale.map(v=>Math.max(1e-6,v*factor));
    else t.scale[s.axis]=Math.max(1e-6,s.start.scale[s.axis]*factor);
  }else if(s.mode==='rotate'){
    let degrees=(dx-dy)*.45*sensitivity;
    if(e.ctrlKey)degrees=Math.round(degrees/5)*5;
    const angle=degrees*Math.PI/180;
    const axis=s.axis===0?[1,0,0]:s.axis===2?[0,0,1]:[0,1,0];
    const dq=qAxis(axis,angle);
    t.rotation=localSpace?qMul(s.start.rotation,dq):qMul(dq,s.start.rotation);
  }
  updateInspector();setDirty();updateToolUI();
}
function confirmTransformDrag(pointerId=null){
  if(!transformDrag)return;
  pushUndo(transformDrag.before);
  transformDrag=null;
  if(pointerId!==null){try{canvas.releasePointerCapture(pointerId);}catch{}}
  setDirty();setStatus('Transform applied');updateToolUI();
}
function cancelTransformDrag(pointerId=null){
  if(!transformDrag)return;
  const before=transformDrag.before;
  transformDrag=null;
  applySnapshot(before);
  if(pointerId!==null){try{canvas.releasePointerCapture(pointerId);}catch{}}
  setDirty();setStatus('Transform cancelled');updateToolUI();
}
function deleteSelected(){if(!model||!selectedKey)return;const before=stateSnapshot();if(selectedKey==='root'){model.visualPresent=false;model.colliderPresent=false;}else if(selectedKey==='visual')model.visualPresent=false;else if(selectedKey==='collider')model.colliderPresent=false;pushUndo(before);refreshAll();setDirty();setStatus(`Deleted ${selectedKey==='collider'?'Box Collider':selectedKey==='visual'?'Geometry':'Object'}`);}

// ---------- UI ----------
function select(key){if(!model)return;selectedKey=key;rebuildHierarchy();updateInspector();selectedValue.textContent=key==='root'?model.objectId:key==='visual'?'Geometry':'Box Collider';}
function rebuildHierarchy(){
  if(!model){hierarchy.className='hierarchy empty';hierarchy.innerHTML='<div class="empty-message">Open a .3ds or .itzfenyxz model.</div>';return;}
  hierarchy.className='hierarchy';hierarchy.innerHTML='';const rows=[['root',model.objectId,'◆',false,!(model.visualPresent||model.colliderPresent)],['visual','Geometry','△',true,!model.visualPresent],['collider','Box Collider','□',true,!model.colliderPresent]];
  for(const [key,name,icon,child,deleted] of rows){const row=document.createElement('div');row.className=`tree-row${child?' child':''}${selectedKey===key?' selected':''}${deleted?' deleted':''}`;row.innerHTML=`<span class="tree-icon">${icon}</span><span></span>`;row.lastElementChild.textContent=name;row.addEventListener('click',()=>select(key));hierarchy.appendChild(row);}
}
function updateInspector(){const t=selectedTransform();const enabled=!!t&&selectedPresent();const e=t?eulerDegFromQ(t.rotation):[0,0,0];for(const input of inspectorInputs){const k=input.dataset.transform,a=Number(input.dataset.axis);input.disabled=!enabled;input.value=enabled?fmt(k==='position'?t.position[a]:k==='scale'?t.scale[a]:e[a]):'';}resetTransformBtn.disabled=!enabled;}
function setDiagnosticValue(element,value,state=''){
  element.textContent=value;
  element.classList.remove('good','warn');
  if(state)element.classList.add(state);
}
function updateSourceDiagnostics(){
  if(!model){
    for(const element of [geometryObjectsValue,geometryVerticesValue,geometryTrianglesValue,markerCountValue,colliderProxyValue,calibrationValue,matrixRecoveryValue])setDiagnosticValue(element,'—');
    sourceWarning.textContent='';sourceWarning.classList.add('hidden');
    return;
  }
  const d=model.mesh?.diagnostics||{};
  const legacyMarkers=(d.removedMarkerObjects||0)+(d.removedMarkerFaces||0);
  const proxyUnits=(d.removedProxyObjects||0)+(d.removedProxyFaces||0);
  setDiagnosticValue(geometryObjectsValue,String(d.geometryObjectCount??model.mesh?.objectRanges?.length??0));
  setDiagnosticValue(geometryVerticesValue,Number(d.vertexCount??model.mesh?.vertices?.length/3??0).toLocaleString());
  setDiagnosticValue(geometryTrianglesValue,Number(d.triangleCount??model.mesh?.indices?.length/3??0).toLocaleString());
  setDiagnosticValue(markerCountValue,String(legacyMarkers),legacyMarkers>0?'good':'');
  setDiagnosticValue(colliderProxyValue,proxyUnits?`${d.removedProxyObjects||0} object / ${d.removedProxyFaces||0} faces`:'Missing',proxyUnits?'good':'warn');
  const calibrationLabel=d.coordinateFrameRecovered
    ?'Unity coordinate frame + exact collider'
    :String(d.calibrationMode||'').startsWith('legacy-markers')
      ?'Legacy coordinate markers + collider'
      :'Uncalibrated';
  setDiagnosticValue(calibrationValue,model.sourceCalibrated?calibrationLabel:'Missing',model.sourceCalibrated?'good':'warn');
  setDiagnosticValue(matrixRecoveryValue,d.matrixFallbackUsed?'Used':'Not needed',d.matrixFallbackUsed?'good':'');
  const issues=[];
  if(!model.sourceCalibrated)issues.push('Precise Unity coordinate calibration is missing. This 3DS may look rotated or scaled differently from Unity and cannot be saved safely. Re-export it from Unity after generating the new coordinate frame.');
  if(!/^[A-Z0-9]{5}$/.test(model.sourceToken||''))issues.push('The converter removed the five-character token; saving will use the exact Object ID instead. Do not rename the 3DS file.');
  if(!proxyUnits&&!String(d.calibrationMode||'').startsWith('legacy-markers'))issues.push('No dedicated collider-proxy faces were removed from Geometry.');
  if(issues.length){sourceWarning.textContent=issues.join(' ');sourceWarning.classList.remove('hidden');}
  else{sourceWarning.textContent='';sourceWarning.classList.add('hidden');}
}
function refreshAll(){
  rebuildHierarchy();updateInspector();if(!model){updateSourceDiagnostics();return;}
  objectIdValue.textContent=model.objectId;sourceValue.textContent=model.sourceName;colliderStateValue.textContent=model.colliderPresent?'Present':'Deleted';colliderSizeValue.textContent=model.colliderBaseSize.map(fmt).join(' × ');
  geometryLayer.checked=showGeometry;colliderLayer.checked=showColliders;gridLayer.checked=showGrid;showCollidersBtn.textContent=showColliders?'Hide Colliders':'Show Colliders';
  const saveable=sourceIsSaveable();saveBtn.disabled=!saveable;saveAsBtn.disabled=!saveable;updateSourceDiagnostics();
}
function resetUIForModel(){geometryLayer.disabled=false;colliderLayer.disabled=false;showCollidersBtn.disabled=false;emptyViewport.classList.add('hidden');selectedKey='root';refreshAll();updateHistory();}
function clearModel(){model=null;selectedKey=null;meshVertexCount=0;meshWireVertexCount=0;history=[];redoStack=[];savedState='';saveHandle=null;activeTool=null;axisConstraint=null;transformDrag=null;updateToolUI();objectIdValue.textContent=sourceValue.textContent=selectedValue.textContent=colliderStateValue.textContent=colliderSizeValue.textContent='—';fileIndicator.textContent='No model loaded';saveBtn.disabled=saveAsBtn.disabled=true;geometryLayer.disabled=colliderLayer.disabled=true;showCollidersBtn.disabled=true;emptyViewport.classList.remove('hidden');rebuildHierarchy();updateInspector();updateSourceDiagnostics();setDirty();updateHistory();}
function loadParsed(mesh,sourceBytes,manifest,sourceName,kind){
  uploadMesh(mesh);
  const fallbackSize=mesh.max.map((v,i)=>Math.max(1e-4,v-mesh.min[i]));
  const fallbackCenter=mesh.min.map((v,i)=>(v+mesh.max[i])/2);
  const parsedBase=mesh.colliderBase||{center:fallbackCenter,size:fallbackSize,rotation:[0,0,0,1],fromMarkers:false};
  const manifestCollider=manifest?.collider;
  const sourceMeta=manifest?.source||{};
  model={
    mesh,
    sourceBytes:sourceBytes.slice(),
    objectId:manifest?.objectId||sanitizeObjectID(sourceName),
    sourceName:sourceMeta.name||manifest?.sourceName||sourceName,
    sourceToken:sourceMeta.token||mesh.sourceToken||'',
    sourceCalibrated:mesh.calibrated===true,
    root:cloneTransform(manifest?.root||identityTransform()),
    visual:cloneTransform(manifest?.visual?.transform||identityTransform()),
    collider:cloneTransform(manifestCollider?.transform||identityTransform()),
    visualPresent:manifest?.visual?.present!==false,
    colliderPresent:manifestCollider?.present!==false,
    colliderBaseCenter:manifestCollider?.baseCenter?[...manifestCollider.baseCenter]:[...parsedBase.center],
    colliderBaseSize:manifestCollider?.baseSize?[...manifestCollider.baseSize]:[...parsedBase.size],
    colliderBaseRotation:manifestCollider?.baseRotation?[...manifestCollider.baseRotation]:[...parsedBase.rotation]
  };
  history=[];redoStack=[];saveHandle=null;resetUIForModel();fileIndicator.textContent=model.sourceName;fitCamera();savedState=persistentState();setDirty();fatalBanner.classList.add('hidden');
  const d=mesh.diagnostics||{};
  const proxyUnits=(d.removedProxyObjects||0)+(d.removedProxyFaces||0);
  const legacyMarkers=(d.removedMarkerObjects||0)+(d.removedMarkerFaces||0);
  const duplicateColliderUnits=(d.removedColliderGeometryObjects||0)+(d.removedColliderGeometryFaces||0);
  const coordinateFrameUnits=(d.removedCoordinateFrameObjects||0)+(d.removedCoordinateFrameFaces||0);
  const summary=`${d.geometryObjectCount??mesh.objectRanges?.length??0} geometry object(s), ${(d.vertexCount??mesh.vertices.length/3).toLocaleString()} vertices, ${(d.triangleCount??mesh.indices.length/3).toLocaleString()} triangles, ${proxyUnits} collider-proxy unit(s) removed${coordinateFrameUnits?`, ${coordinateFrameUnits} coordinate-frame unit(s) removed`:''}${duplicateColliderUnits?`, ${duplicateColliderUnits} duplicate collider unit(s) removed`:''}${legacyMarkers?`, ${legacyMarkers} legacy marker unit(s) removed`:''}`;
  const warnings=[];
  if(!model.sourceCalibrated)warnings.push('precise Unity coordinate frame missing');
  if(!model.sourceToken)warnings.push('identity token missing');
  if(!proxyUnits&&d.calibrationMode!=='legacy-markers')warnings.push('no collider proxy removed');
  const recovery=d.matrixFallbackUsed?' — MESH_MATRIX recovery used':'';
  setStatus(`${kind==='3ds'?'Imported':'Opened'} ${model.sourceName} — ${summary}${recovery}${warnings.length?` — WARNING: ${warnings.join('; ')}`:''}`);
}
async function openFile(file){
  if(!file)return;try{if(dirty&&!confirm('Discard unsaved changes?'))return;setStatus(`Opening ${file.name}…`);const bytes=new Uint8Array(await file.arrayBuffer()),ext=file.name.toLowerCase().split('.').pop();if(ext==='3ds'){const mesh=parse3DS(bytes);loadParsed(mesh,bytes,null,file.name,'3ds');}else if(ext==='itzfenyxz'){const data=await decodeITZF(bytes);const mesh=parse3DS(data.source);loadParsed(mesh,data.source,data.manifest,file.name,'itzf');}else throw new Error('Supported formats: .3ds and .itzfenyxz');}catch(e){reportError(e,'Open file');toast('Open failed');setStatus('Open failed');}}

async function saveAs(){
  if(!model)return;
  try{
    validateModelForSave();
    const suggested=`${model.objectId}.itzfenyxz`;
    let handle=null;

    // Request the native file handle immediately from the user's click. Doing
    // this before asynchronous encoding preserves browser user activation.
    if(typeof window.showSaveFilePicker==='function'){
      handle=await window.showSaveFilePicker({
        suggestedName:suggested,
        types:[{description:'ITZFENYXZ Model',accept:{'application/octet-stream':['.itzfenyxz']}}]
      });
    }

    const bytes=await encodeITZF(manifestFromModel(),model.sourceBytes);
    if(handle){
      const writable=await handle.createWritable();
      await writable.write(bytes);
      await writable.close();
      saveHandle=handle;
    }else{
      const blob=new Blob([bytes],{type:'application/octet-stream'});
      const link=document.createElement('a');
      link.href=URL.createObjectURL(blob);
      link.download=suggested;
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(()=>URL.revokeObjectURL(link.href),1000);
    }
    savedState=persistentState();
    setDirty();
    setStatus(`Saved ${suggested}`);
    toast('Saved .itzfenyxz');
  }catch(e){
    if(e?.name!=='AbortError')reportError(e,'Save');
  }
}
async function save(){if(!model)return;if(!saveHandle)return saveAs();try{validateModelForSave();const bytes=await encodeITZF(manifestFromModel(),model.sourceBytes),w=await saveHandle.createWritable();await w.write(bytes);await w.close();savedState=persistentState();setDirty();setStatus('Saved');toast('Saved');}catch(e){if(e?.name!=='AbortError')reportError(e,'Save');}}

openBtn.addEventListener('click',()=>fileInput.click());fileInput.addEventListener('change',()=>{const f=fileInput.files?.[0];fileInput.value='';openFile(f);});
saveBtn.addEventListener('click',save);saveAsBtn.addEventListener('click',saveAs);
moveBtn.addEventListener('click',()=>setActiveTool('move'));rotateBtn.addEventListener('click',()=>setActiveTool('rotate'));scaleBtn.addEventListener('click',()=>setActiveTool('scale'));
for(const button of axisButtons){button.addEventListener('click',()=>setAxis(button.dataset.axis==='free'?null:Number(button.dataset.axis)));}
helpBtn.addEventListener('click',()=>{const opened=window.open(new URL('help.pdf',window.location.href).href,'itzfenyxz-help');if(opened){try{opened.opener=null;}catch{}setStatus('Help opened');}else{toast('Help window was blocked');}});
spaceBtn.addEventListener('click',()=>{localSpace=!localSpace;spaceBtn.textContent=localSpace?'Local':'World';viewportBadge.textContent=localSpace?'LOCAL':'WORLD';});
frontBtn.addEventListener('click',()=>{camera.yaw=0;camera.pitch=0;});rightBtn.addEventListener('click',()=>{camera.yaw=Math.PI/2;camera.pitch=0;});topBtn.addEventListener('click',()=>{camera.yaw=0;camera.pitch=Math.PI/2-.001;});frameBtn.addEventListener('click',fitCamera);
geometryLayer.addEventListener('change',()=>{showGeometry=geometryLayer.checked;refreshAll();});colliderLayer.addEventListener('change',()=>{showColliders=colliderLayer.checked;refreshAll();});gridLayer.addEventListener('change',()=>{showGrid=gridLayer.checked;refreshAll();});
showCollidersBtn.addEventListener('click',()=>{showColliders=!showColliders;refreshAll();});
resetTransformBtn.addEventListener('click',()=>{const t=selectedTransform();if(!t)return;const before=stateSnapshot();Object.assign(t,identityTransform());pushUndo(before);refreshAll();setDirty();});
for(const input of inspectorInputs){input.addEventListener('change',()=>{const t=selectedTransform();if(!t||!selectedPresent())return;const value=Number(input.value);if(!Number.isFinite(value)){updateInspector();return;}const before=stateSnapshot(),k=input.dataset.transform,a=Number(input.dataset.axis);if(k==='position')t.position[a]=value;else if(k==='scale')t.scale[a]=Math.abs(value)<1e-6?(value<0?-1e-6:1e-6):value;else{const e=eulerDegFromQ(t.rotation);e[a]=value;t.rotation=qFromEulerDeg(e);}pushUndo(before);setDirty();updateInspector();});}

viewportShell.addEventListener('dragover',e=>{e.preventDefault();});viewportShell.addEventListener('drop',e=>{e.preventDefault();openFile(e.dataTransfer?.files?.[0]);});
window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});
window.addEventListener('keydown',e=>{
  const tag=document.activeElement?.tagName;if(tag==='INPUT'&&document.activeElement.type==='number')return;
  const key=e.key.toLowerCase();
  if((e.ctrlKey||e.metaKey)&&key==='o'){e.preventDefault();fileInput.click();return;}
  if((e.ctrlKey||e.metaKey)&&key==='s'){e.preventDefault();e.shiftKey?saveAs():save();return;}
  if((e.ctrlKey||e.metaKey)&&key==='z'){e.preventDefault();e.shiftKey?redo():undo();return;}
  if((e.ctrlKey||e.metaKey)&&key==='y'){e.preventDefault();redo();return;}
  if(transformDrag){if(key==='x')setAxis(0);else if(key==='y')setAxis(1);else if(key==='z')setAxis(2);else if(key==='0')setAxis(null);else if(key==='escape')cancelTransformDrag();return;}
  if(key==='x'&&activeTool)setAxis(0);else if(key==='y'&&activeTool)setAxis(1);else if(key==='z'&&activeTool)setAxis(2);else if(key==='0'&&activeTool)setAxis(null);else if(key==='escape'&&activeTool){activeTool=null;updateToolUI();}else if(key==='g')setActiveTool('move');else if(key==='r')setActiveTool('rotate');else if(key==='s')setActiveTool('scale');else if(key==='delete')deleteSelected();else if(key==='c'){showColliders=!showColliders;refreshAll();}else if(key==='f')fitCamera();else if(key==='1'){camera.yaw=0;camera.pitch=0;}else if(key==='3'){camera.yaw=Math.PI/2;camera.pitch=0;}else if(key==='7'){camera.yaw=0;camera.pitch=Math.PI/2-.001;}
});

clearModel();
window.__itzfReady = true;
setStatus('Ready. Open a .3ds model or an existing .itzfenyxz update.');
// Static GitHub Pages / PWA runtime. There is no localhost server, launcher,
// background process, port, heartbeat or taskkill lifecycle to get stuck.
let deferredInstallPrompt = null;
window.addEventListener('beforeinstallprompt', event => {
  event.preventDefault();
  deferredInstallPrompt = event;
  installBtn?.classList.remove('hidden');
});
installBtn?.addEventListener('click', async () => {
  if (!deferredInstallPrompt) return;
  deferredInstallPrompt.prompt();
  try { await deferredInstallPrompt.userChoice; } catch {}
  deferredInstallPrompt = null;
  installBtn.classList.add('hidden');
});
window.addEventListener('appinstalled', () => {
  deferredInstallPrompt = null;
  installBtn?.classList.add('hidden');
  setStatus('ITZFENYXZ Editor installed.');
});
if ('serviceWorker' in navigator && location.protocol === 'https:') {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch(error => console.warn('Service worker registration failed', error));
  });
}
