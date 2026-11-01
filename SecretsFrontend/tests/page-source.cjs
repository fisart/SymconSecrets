'use strict';
const fs=require('node:fs');const path=require('node:path');
module.exports=()=>fs.readFileSync(path.join(__dirname,'../page.html'),'utf8').replace('%%NATIVE_PANELS%%',fs.readFileSync(path.join(__dirname,'../native-panels.html'),'utf8')).replace('/* %%NATIVE_ADMIN%% */',fs.readFileSync(path.join(__dirname,'../native-admin.js'),'utf8'));
