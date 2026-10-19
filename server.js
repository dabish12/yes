'use strict';
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const {DatabaseSync}=require('node:sqlite');
const PORT=+process.env.PORT||3000, PROD=process.env.NODE_ENV==='production';
const db=new DatabaseSync(process.env.DB_PATH||path.join(__dirname,'ddeo.db'));
db.exec('PRAGMA journal_mode=WAL;'+fs.readFileSync(path.join(__dirname,'schema.sql'),'utf8'));
const q=(s,...a)=>db.prepare(s).all(...a), q1=(s,...a)=>db.prepare(s).get(...a), run=(s,...a)=>db.prepare(s).run(...a);
const now=()=>Date.now(), rnd=n=>crypto.randomBytes(n).toString('hex');
const hash=p=>{const s=rnd(16);return s+':'+crypto.scryptSync(p,s,64).toString('hex')};
const check=(p,h)=>{const [s,x]=h.split(':');const y=crypto.scryptSync(p,s,64);return crypto.timingSafeEqual(y,Buffer.from(x,'hex'))};
const audit=(u,a)=>run('INSERT INTO audit(ts,user_id,action) VALUES(?,?,?)',now(),u,a);
class E extends Error{constructor(c,m){super(m);this.c=c}}
const need=(c,m,code=400)=>{if(!c)throw new E(code,m)};
// first run: create Education Office admin
if(!q1("SELECT 1 x FROM users WHERE role='office'")){
  const pw=process.env.ADMIN_PASSWORD||rnd(6);
  run("INSERT INTO users(username,pw,role) VALUES('office',?,'office')",hash(pw));
  console.log('Created user "office" with temporary password:',pw,'(change at first login)');
}
const ipFails=new Map();
function ipLimited(ip){const f=ipFails.get(ip)||{n:0,t:now()};if(now()-f.t>9e5){f.n=0;f.t=now()}ipFails.set(ip,f);return f}
function body(req){return new Promise((ok,no)=>{let b='',n=0;req.on('data',c=>{n+=c.length;if(n>1e5){no(new E(413,'Too large'));req.destroy()}else b+=c});
  req.on('end',()=>{try{ok(b?JSON.parse(b):{})}catch{no(new E(400,'Bad JSON'))}})})}
const str=(v,max=100)=>{need(typeof v==='string'&&v.trim()&&v.length<=max,'Invalid text');return v.trim()};
function session(req){const m=/(?:^|; )sid=([a-f0-9]+)/.exec(req.headers.cookie||'');if(!m)return null;
  const s=q1('SELECT s.*,u.username,u.role,u.school_id,u.must_change FROM sessions s JOIN users u ON u.id=s.user_id WHERE token=?',m[1]);
  if(!s||s.expires<now())return null;return s}
const role=(s,...r)=>{need(s,'Login required',401);need(r.includes(s.role),'Forbidden',403)};
function weightsOf(sid){return q1('SELECT w_test,w_mid,w_final FROM schools WHERE id=?',sid)}
function total(m){return (m.test||0)+(m.mid||0)+(m.final||0)}
function teacherCan(s,subject,grade,section){return !!q1('SELECT 1 x FROM assignments WHERE teacher_id=? AND subject_id=? AND grade=? AND section=?',s.user_id,subject,grade,section)}

const routes={
'POST /api/login':async(req,res,s,b,ip)=>{
  const f=ipLimited(ip);need(f.n<20,'Too many attempts',429);
  const u=q1('SELECT * FROM users WHERE username=?',String(b.username||''));
  need(!u||u.locked_until<now(),'Account locked. Try later.',429);
  if(!u||!check(String(b.password||''),u.pw)){f.n++;if(u){const n=u.fails+1;run('UPDATE users SET fails=?,locked_until=? WHERE id=?',n,n>=5?now()+9e5:0,u.id)}throw new E(401,'Wrong username or password')}
  run('UPDATE users SET fails=0,locked_until=0 WHERE id=?',u.id);
  const token=rnd(32),csrf=rnd(16);run('INSERT INTO sessions VALUES(?,?,?,?)',token,u.id,csrf,now()+288e5);audit(u.id,'login');
  res.setHeader('Set-Cookie',`sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${PROD?'; Secure':''}`);
  return {csrf,role:u.role,must_change:!!u.must_change}},
'POST /api/logout':async(req,res,s)=>{if(s)run('DELETE FROM sessions WHERE token=?',s.token);res.setHeader('Set-Cookie','sid=; Max-Age=0; Path=/');return {ok:1}},
'GET /api/me':async(req,res,s)=>{need(s,'Login required',401);return {username:s.username,role:s.role,school_id:s.school_id,must_change:!!s.must_change,csrf:s.csrf}},
'POST /api/password':async(req,res,s,b)=>{role(s,'office','school_admin','teacher');
  const u=q1('SELECT * FROM users WHERE id=?',s.user_id);need(check(String(b.old||''),u.pw),'Old password wrong');
  need(typeof b.new==='string'&&b.new.length>=10&&b.new!==b.old,'New password: at least 10 characters, different from old');
  run('UPDATE users SET pw=?,must_change=0 WHERE id=?',hash(b.new),u.id);audit(u.id,'password change');return {ok:1}},
// Education Office
'GET /api/schools':async(req,res,s)=>{role(s,'office');return q('SELECT sc.*,(SELECT COUNT(*) FROM students WHERE school_id=sc.id) students FROM schools sc')},
'POST /api/schools':async(req,res,s,b)=>{role(s,'office');need(!s.must_change,'Change password first',403);
  const code=str(b.code,10).toUpperCase(),name=str(b.name),user=str(b.admin_username,40),pw=str(b.admin_password,100);need(pw.length>=10,'Temporary password too short');
  db.exec('BEGIN');try{const r=run('INSERT INTO schools(code,name) VALUES(?,?)',code,name);
  run("INSERT INTO users(username,pw,role,school_id) VALUES(?,?,'school_admin',?)",user,hash(pw),r.lastInsertRowid);db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw new E(400,'Duplicate school code or username')}
  audit(s.user_id,'school '+code);return {ok:1}},
// School admin
'POST /api/weights':async(req,res,s,b)=>{role(s,'school_admin');const t=+b.w_test,m=+b.w_mid,f=+b.w_final;
  need([t,m,f].every(x=>Number.isInteger(x)&&x>=0)&&t+m+f===100,'Weights must be whole numbers totaling 100');
  need(!q1('SELECT 1 x FROM marks mk JOIN students st ON st.id=mk.student_id WHERE st.school_id=? LIMIT 1',s.school_id),'Marks already exist; weights locked');
  run('UPDATE schools SET w_test=?,w_mid=?,w_final=? WHERE id=?',t,m,f,s.school_id);return {ok:1}},
'POST /api/subjects':async(req,res,s,b)=>{role(s,'school_admin');
  need(q1('SELECT COUNT(*) n FROM subjects WHERE school_id=?',s.school_id).n<16,'Maximum 16 subjects');
  try{run('INSERT INTO subjects(school_id,name) VALUES(?,?)',s.school_id,str(b.name))}catch{throw new E(400,'Subject exists')}return {ok:1}},
'GET /api/subjects':async(req,res,s)=>{role(s,'school_admin','teacher');return q('SELECT id,name FROM subjects WHERE school_id=?',s.school_id)},
'POST /api/students':async(req,res,s,b)=>{role(s,'school_admin');
  const grade=+b.grade,year=+b.year;need(grade>=9&&grade<=12&&Number.isInteger(year),'Invalid grade/year');
  need(/^\d{4}-\d{2}-\d{2}$/.test(b.birth_date||''),'Birth date must be YYYY-MM-DD');
  const sc=q1('SELECT code FROM schools WHERE id=?',s.school_id);
  const n=q1('SELECT COUNT(*) n FROM students WHERE school_id=? AND year=?',s.school_id,year).n+1;
  const sid=`${sc.code}/${String(n).padStart(4,'0')}/${year}`; // PLACEHOLDER format: replace with your documented ID format
  run('INSERT INTO students(sid,school_id,name,birth_date,grade,section,year) VALUES(?,?,?,?,?,?,?)',sid,s.school_id,str(b.name),b.birth_date,grade,str(b.section,5).toUpperCase(),year);
  audit(s.user_id,'student '+sid);return {sid}},
'GET /api/students':async(req,res,s)=>{role(s,'school_admin');return q('SELECT id,sid,name,grade,section,year FROM students WHERE school_id=? ORDER BY grade,section,name',s.school_id)},
'POST /api/teachers':async(req,res,s,b)=>{role(s,'school_admin');
  const sub=q1('SELECT id FROM subjects WHERE id=? AND school_id=?',+b.subject_id,s.school_id);need(sub,'Subject not in your school');
  const pw=str(b.password,100);need(pw.length>=10,'Temporary password too short');
  let t=q1("SELECT id FROM users WHERE username=? AND role='teacher' AND school_id=?",str(b.username,40),s.school_id);
  if(!t){try{t={id:run("INSERT INTO users(username,pw,role,school_id) VALUES(?,?,'teacher',?)",b.username.trim(),hash(pw),s.school_id).lastInsertRowid}}catch{throw new E(400,'Username taken')}}
  run('INSERT OR IGNORE INTO assignments VALUES(?,?,?,?)',t.id,sub.id,+b.grade,str(b.section,5).toUpperCase());return {ok:1}},
'POST /api/marks/reset':async(req,res,s,b)=>{role(s,'school_admin');
  run('UPDATE marks SET submitted=0 WHERE subject_id IN(SELECT id FROM subjects WHERE school_id=?) AND subject_id=? AND semester=? AND student_id IN(SELECT id FROM students WHERE grade=? AND section=?)',s.school_id,+b.subject_id,+b.semester,+b.grade,str(b.section,5).toUpperCase());
  audit(s.user_id,'reset marks');return {ok:1}},
// Subject teacher
'GET /api/marks':async(req,res,s,b,ip,url)=>{role(s,'teacher');const p=url.searchParams,sub=+p.get('subject_id'),g=+p.get('grade'),sec=(p.get('section')||'').toUpperCase(),sem=+p.get('semester');
  need(teacherCan(s,sub,g,sec),'Not assigned',403);
  return q('SELECT st.id student_id,st.sid,st.name,mk.test,mk.mid,mk.final,COALESCE(mk.submitted,0) submitted FROM students st LEFT JOIN marks mk ON mk.student_id=st.id AND mk.subject_id=? AND mk.semester=? WHERE st.school_id=? AND st.grade=? AND st.section=? ORDER BY st.name',sub,sem,s.school_id,g,sec)},
'POST /api/marks':async(req,res,s,b)=>{role(s,'teacher');const st=q1('SELECT * FROM students WHERE id=? AND school_id=?',+b.student_id,s.school_id);need(st,'Student not found');
  need(teacherCan(s,+b.subject_id,st.grade,st.section),'Not assigned',403);const w=weightsOf(s.school_id),sem=+b.semester;need(sem===1||sem===2,'Semester 1 or 2');
  const vals=[['test',w.w_test],['mid',w.w_mid],['final',w.w_final]].map(([k,mx])=>{const v=b[k];if(v===null||v===''||v===undefined)return null;const n=Number(v);need(Number.isFinite(n)&&n>=0&&n<=mx,`${k} must be 0 to ${mx}`);return n});
  const ex=q1('SELECT submitted FROM marks WHERE student_id=? AND subject_id=? AND semester=?',st.id,+b.subject_id,sem);need(!ex||!ex.submitted,'Marks submitted and sealed',409);
  run('INSERT INTO marks(student_id,subject_id,semester,test,mid,final) VALUES(?,?,?,?,?,?) ON CONFLICT(student_id,subject_id,semester) DO UPDATE SET test=excluded.test,mid=excluded.mid,final=excluded.final',st.id,+b.subject_id,sem,...vals);return {ok:1}},
'POST /api/marks/submit':async(req,res,s,b)=>{role(s,'teacher');const g=+b.grade,sec=str(b.section,5).toUpperCase();need(teacherCan(s,+b.subject_id,g,sec),'Not assigned',403);
  run('UPDATE marks SET submitted=1 WHERE subject_id=? AND semester=? AND student_id IN(SELECT id FROM students WHERE school_id=? AND grade=? AND section=?)',+b.subject_id,+b.semester,s.school_id,g,sec);audit(s.user_id,'submit marks');return {ok:1}},
// Student (public, verified by student ID + birth date, only sealed marks)
'POST /api/result':async(req,res,s,b,ip)=>{const f=ipLimited(ip);need(f.n<20,'Too many attempts',429);
  const st=q1('SELECT * FROM students WHERE sid=? AND birth_date=?',String(b.sid||''),String(b.birth_date||''));if(!st){f.n++;throw new E(404,'No matching student')}
  const rows=q('SELECT sb.name subject,mk.semester,mk.test,mk.mid,mk.final FROM marks mk JOIN subjects sb ON sb.id=mk.subject_id WHERE mk.student_id=? AND mk.submitted=1 ORDER BY sb.name,mk.semester',st.id);
  const out=rows.map(r=>({subject:r.subject,semester:r.semester,total:total(r)}));
  const avg=out.length?out.reduce((a,r)=>a+r.total,0)/out.length:null;return {name:st.name,sid:st.sid,grade:st.grade,results:out,average:avg}}
};
const HDR={'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Cache-Control':'no-store',
 'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"};
http.createServer(async(req,res)=>{
  for(const k in HDR)res.setHeader(k,HDR[k]);if(PROD)res.setHeader('Strict-Transport-Security','max-age=31536000');
  const url=new URL(req.url,'http://x');
  try{
    if(url.pathname.startsWith('/api/')){
      const h=routes[req.method+' '+url.pathname];need(h,'Not found',404);
      const s=session(req),b=req.method==='POST'?await body(req):{};
      if(req.method==='POST'&&s&&url.pathname!=='/api/login')need(req.headers['x-csrf']===s.csrf,'CSRF check failed',403);
      if(s&&s.must_change&&!['/api/password','/api/logout','/api/me'].includes(url.pathname))throw new E(403,'Change your password first');
      const out=await h(req,res,s,b,req.socket.remoteAddress,url);res.setHeader('Content-Type','application/json');res.end(JSON.stringify(out));
    }else{const f=url.pathname==='/app.js'?'app.js':'index.html';
      res.setHeader('Content-Type',f.endsWith('.js')?'text/javascript':'text/html; charset=utf-8');res.end(fs.readFileSync(path.join(__dirname,'public',f)))}
  }catch(e){const c=e.c||500;if(c===500)console.error(e);res.statusCode=c;res.setHeader('Content-Type','application/json');res.end(JSON.stringify({error:c===500?'Server error':e.message}))}
}).listen(PORT,()=>console.log('DDEO-SRATMS on port',PORT));
