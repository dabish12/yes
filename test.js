// Run: npm test  (starts its own server on a temp DB)
const {spawn}=require('child_process');const fs=require('fs');const DB='/tmp/t.db';[DB,DB+'-wal',DB+'-shm'].forEach(f=>fs.rmSync(f,{force:true}));
const p=spawn('node',['--no-warnings','server.js'],{env:{...process.env,PORT:3999,DB_PATH:DB,ADMIN_PASSWORD:'temp-Office-1'}});
let fails=0;const ok=(n,c)=>{console.log(c?'PASS':'FAIL',n);if(!c)fails++};
const S=()=>{let ck='',cs='';return async(m,u,b)=>{const r=await fetch('http://localhost:3999'+u,{method:m,headers:{'Content-Type':'application/json',cookie:ck,'x-csrf':cs},body:b?JSON.stringify(b):undefined});
 const sc=r.headers.get('set-cookie');if(sc)ck=sc.split(';')[0];const j=await r.json();if(j.csrf)cs=j.csrf;return {s:r.status,j}}};
setTimeout(async()=>{try{
 const o=S(),a=S(),t=S(),t2=S();
 ok('bad login rejected',(await o('POST','/api/login',{username:'office',password:'x'})).s===401);
 await o('POST','/api/login',{username:'office',password:'temp-Office-1'});
 ok('must change password first',(await o('POST','/api/schools',{})).s===403);
 await o('POST','/api/password',{old:'temp-Office-1',new:'Office-new-pass1'});
 for(const c of['AAA','BBB'])await o('POST','/api/schools',{code:c,name:c+' School',admin_username:'admin'+c,admin_password:'tempadmin-'+c});
 for(const c of['AAA','BBB']){const x=S();await x('POST','/api/login',{username:'admin'+c,password:'tempadmin-'+c});await x('POST','/api/password',{old:'tempadmin-'+c,new:'Admin-new-'+c});globalThis[c]=x}
 ok('admin cannot register schools',(await AAA('POST','/api/schools',{code:'X'})).s===403);
 await AAA('POST','/api/subjects',{name:'Math'});await AAA('POST','/api/students',{name:'Test Student',birth_date:'2008-01-01',grade:9,section:'a',year:2018});
 ok('weights must total 100',(await AAA('POST','/api/weights',{w_test:10,w_mid:10,w_final:10})).s===400);
 await AAA('POST','/api/teachers',{username:'tch',password:'tempteach-12',subject_id:1,grade:9,section:'A'});
 await t('POST','/api/login',{username:'tch',password:'tempteach-12'});await t('POST','/api/password',{old:'tempteach-12',new:'Teach-new-pass'});
 ok('score above max rejected',(await t('POST','/api/marks',{student_id:1,subject_id:1,semester:1,test:25,mid:10,final:10})).s===400);
 ok('valid marks saved',(await t('POST','/api/marks',{student_id:1,subject_id:1,semester:1,test:18,mid:25,final:40})).s===200);
 ok('school B cannot see school A students',(await BBB('GET','/api/students')).j.length===0);
 ok('no CSRF header rejected',(await fetch('http://localhost:3999/api/logout',{method:'POST'})).status!==500);
 await t('POST','/api/marks/submit',{subject_id:1,grade:9,section:'A',semester:1});
 ok('sealed marks cannot change',(await t('POST','/api/marks',{student_id:1,subject_id:1,semester:1,test:1,mid:1,final:1})).s===409);
 const r=await o('POST','/api/result',{sid:'AAA/0001/2018',birth_date:'2008-01-01'});ok('student result total 83',r.j.results?.[0]?.total===83);
 ok('wrong birth date rejected',(await o('POST','/api/result',{sid:'AAA/0001/2018',birth_date:'2009-01-01'})).s===404);
 for(let i=0;i<5;i++)await t2('POST','/api/login',{username:'tch',password:'bad'});
 ok('account locks after 5 failures',(await t2('POST','/api/login',{username:'tch',password:'Teach-new-pass'})).s===429);
}catch(e){console.log('ERROR',e);fails++}p.kill();process.exit(fails?1:0)},1200);
