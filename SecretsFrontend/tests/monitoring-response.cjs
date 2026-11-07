'use strict';
const {execFileSync}=require('node:child_process');
const path=require('node:path');
module.exports=function(n){
 const raw={...n,serverTime:n.serverTime||1793656603,overview:n.overview||{globalValues:1,localValues:0,credentials:1,hardwareCredentials:0,magicCredentials:0,machines:0,providers:0,pendingEffects:0,storage:n.info}};
 return JSON.parse(execFileSync(process.env.PHP_BINARY||'php',[path.join(__dirname,'monitoring-view-json.php')],{input:JSON.stringify(raw),encoding:'utf8',maxBuffer:8*1024*1024}));
};
