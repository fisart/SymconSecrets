'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {JSDOM}=require('jsdom');
const source=fs.readFileSync(path.join(__dirname,'../authorize.html'),'utf8');
const script=source.match(/<script nonce="%%NONCE%%">([\s\S]*?)<\/script>/)[1].replace('%%BOOT%%',JSON.stringify({origin:'https://secrets.example.test',path:'/hook/secrets_frontend_123'}));
const tick=()=>new Promise(resolve=>setTimeout(resolve,0));
const credential={type:'public-key',rawId:new Uint8Array([1]).buffer,response:{clientDataJSON:new Uint8Array([2]).buffer,authenticatorData:new Uint8Array([3]).buffer,signature:new Uint8Array([4]).buffer,userHandle:null}};
async function fixture({hash='#legacy-return=%2Fhook%2Flibrary',session=false,promptError=false,verified=true,secure=true,framed=false,waitVerify=false}={}){
 const dom=new JSDOM(source.replace(/<script[\s\S]*?<\/script>/,'')),calls=[],targets=[],events={};let gets=0,resolveVerify;
 const window={isSecureContext:secure,PublicKeyCredential:class{},addEventListener:(name,fn)=>events[name]=fn};window.self=window;window.top=framed?{}:window;
 const ctx={window,document:dom.window.document,location:{protocol:'https:',origin:'https://secrets.example.test',hash,replace:value=>targets.push(value)},URLSearchParams,DOMException,AbortController,Uint8Array,setTimeout,clearTimeout,atob,btoa,navigator:{credentials:{get:async()=>{gets++;if(promptError){promptError=false;throw new DOMException('Gesture needed','NotAllowedError');}return credential;}}},fetch:async(url,options)=>{assert.equal(url,'/hook/secrets_frontend_123');assert.equal(options.credentials,'same-origin');assert.equal(options.redirect,'error');const request=JSON.parse(options.body);calls.push(request);if(request.action==='portalAuthOptions')return{ok:true,json:async()=>session?{authenticated:true}:{challengeId:'id',options:{challenge:'AQ',allowCredentials:[{id:'AQ',type:'public-key'}]}}};assert.equal(request.action,'authVerify');if(waitVerify)await new Promise(resolve=>resolveVerify=resolve);return{ok:true,json:async()=>({authenticated:true,portalAuthenticated:verified})};}};
 vm.createContext(ctx);vm.runInContext(script,ctx);await tick();await tick();return{dom,calls,targets,events,gets:()=>gets,resolveVerify:()=>resolveVerify(),$:id=>dom.window.document.getElementById(id)};
}
(async()=>{
 let f=await fixture({session:true});assert.equal(f.calls.length,1);assert.equal(f.gets(),0);assert.deepEqual(f.targets,['/hook/library']);f.dom.window.close();
 f=await fixture();assert.deepEqual(f.calls.map(c=>c.action),['portalAuthOptions','authVerify']);assert.equal(f.gets(),1);assert.deepEqual(f.targets,['/hook/library']);assert.equal(f.calls[1].data.credential.response.signature,'BA');assert.equal(f.$('tree'),null);f.dom.window.close();
 f=await fixture({promptError:true});assert.deepEqual(f.targets,[]);assert.match(f.$('message').textContent,/Tap Continue/);assert.equal(f.$('continue').disabled,false);f.$('continue').click();await tick();await tick();assert.deepEqual(f.targets,['/hook/library']);f.dom.window.close();
 f=await fixture({verified:false});assert.deepEqual(f.targets,[]);assert.match(f.$('message').textContent,/not approved/);f.dom.window.close();
 for(const hash of ['', '#legacy-return=https%3A%2F%2Fevil.test','#legacy-return=%2F%2Fevil.test','#legacy-return=%2Fhook%2Flibrary%3Fx%3D1','#legacy-return=%2Fhook%2Fsecrets_49800','#legacy-return=%2Fhook%2Flibrary&legacy-return=%2Fhook%2Fportal','#legacy-return=%2Fhook%2Flibrary%0A']){f=await fixture({hash});assert.equal(f.calls.length,0);assert.deepEqual(f.targets,[]);assert.equal(f.$('continue').disabled,true);f.dom.window.close();}
 for(const options of [{secure:false},{framed:true}]){f=await fixture(options);assert.equal(f.calls.length,0);assert.equal(f.gets(),0);f.dom.window.close();}
 f=await fixture({waitVerify:true});assert.equal(f.calls.length,2);f.$('cancel').click();f.resolveVerify();await tick();assert.deepEqual(f.targets,[]);assert.match(f.$('message').textContent,/cancelled/);f.dom.window.close();
 f=await fixture({waitVerify:true});f.events.pagehide();f.resolveVerify();await tick();assert.deepEqual(f.targets,[]);f.events.pageshow({persisted:true});assert.equal(f.calls.length,2);assert.match(f.$('message').textContent,/Tap Continue/);f.dom.window.close();
 console.log('PASS minimal authorization: one-call session reuse, automatic two-call passkey login, tap fallback, limited-right denial, bounded local targets, cancel/navigation races and no dashboard requests');
})().catch(error=>{console.error(error);process.exitCode=1;});
