const enc = new TextEncoder();
const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}});
const hex=b=>Array.from(new Uint8Array(b)).map(x=>x.toString(16).padStart(2,'0')).join('');
const rand=()=>crypto.randomUUID();
async function digest(s){return hex(await crypto.subtle.digest('SHA-256',enc.encode(s)))}
async function hash(p,s,it=210000){const k=await crypto.subtle.importKey('raw',enc.encode(p),'PBKDF2',false,['deriveBits']);return hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:enc.encode(s),iterations:it,hash:'SHA-256'},k,256));}
const cookie=(r,n)=>r.headers.get('cookie')?.split(';').map(s=>s.trim()).find(s=>s.startsWith(n+'='))?.slice(n.length+1);
async function auth(r,db){const raw=cookie(r,'sid');if(!raw)return null;const sid=await digest(raw);const s=await db.prepare('SELECT s.*,u.company_id,u.role,u.name,u.email,u.active,u.password_version AS current_version FROM pdv_sessions s JOIN pdv_users u ON u.id=s.user_id WHERE s.id=?').bind(sid).first();return s&&s.expires_at>Date.now()&&s.active&&s.password_version===s.current_version?s:null;}
async function audit(db,u,action,detail=''){await db.prepare('INSERT INTO pdv_audit_logs(id,company_id,user_id,action,detail) VALUES(?,?,?,?,?)').bind(rand(),u.company_id,u.user_id,action,detail).run();}
const parse=async r=>{try{return await r.json()}catch{return {}}};
const sessionCookie=(id,max=86400)=>`sid=${id}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${max}`;
export default {async fetch(request,env){
 const url=new URL(request.url),path=url.pathname,db=env.SYSTEME_DB;
 if(!path.startsWith('/api/'))return env.ASSETS.fetch(request);
 if(!db||!env.SYSTEME_KV)return json({error:'Bindings D1/KV absents'},503);
 if(request.method==='POST'&&!['/api/login','/api/register','/api/setup'].includes(path)){const origin=request.headers.get('origin');if(origin&&origin!==url.origin)return json({error:'Origine refusée'},403);}
 try{
 if(path==='/api/setup'&&request.method==='POST'){
  if(env.ENABLE_INITIAL_SETUP!=='true'||!env.SETUP_TOKEN||request.headers.get('x-setup-token')!==env.SETUP_TOKEN)return json({error:'Initialisation désactivée'},403);
  if(!env.SUPERADMIN_EMAIL||!env.SUPERADMIN_INITIAL_PASSWORD||!env.SESSION_PEPPER)return json({error:'Secrets Super Admin manquants'},503);
  const existing=await db.prepare("SELECT id FROM pdv_users WHERE role='superadmin' LIMIT 1").first();if(existing)return json({error:'Super Admin déjà initialisé'},409);
  const id=rand(),salt=rand(),pwd=env.SUPERADMIN_INITIAL_PASSWORD;
  if(pwd.length<12)return json({error:'Mot de passe initial trop court (12 caractères minimum)'},400);
  await db.batch([db.prepare("INSERT INTO pdv_users(id,name,email,role) VALUES(?,? ,?,'superadmin')").bind(id,'Super Admin',env.SUPERADMIN_EMAIL.toLowerCase()),db.prepare('INSERT INTO pdv_user_credentials(user_id,salt,password_hash) VALUES(?,?,?)').bind(id,salt,await hash(pwd,salt))]);return json({ok:true});
 }
 if(path==='/api/register'&&request.method==='POST'){
  const b=await parse(request);if(!b.company||!b.name||!b.email||!b.password||b.password.length<12)return json({error:'Informations incomplètes ou mot de passe inférieur à 12 caractères'},400);
  const cid=rand(),uid=rand(),salt=rand(),email=String(b.email).trim().toLowerCase();
  await db.batch([db.prepare("INSERT INTO pdv_companies(id,name,email,phone,city,plan_expires) VALUES(?,?,?,?,?,datetime('now','+10 days'))").bind(cid,b.company,email,b.phone||'',b.city||''),db.prepare("INSERT INTO pdv_users(id,company_id,name,email,role) VALUES(?,?,?,?,'admin')").bind(uid,cid,b.name,email),db.prepare('INSERT INTO pdv_user_credentials(user_id,salt,password_hash) VALUES(?,?,?)').bind(uid,salt,await hash(b.password,salt))]);return json({ok:true});
 }
 if(path==='/api/login'&&request.method==='POST'){
  const b=await parse(request),email=String(b.email||'').trim().toLowerCase(),ip=request.headers.get('cf-connecting-ip')||'unknown';
  const key='login:ip:'+ip, emailKey='login:email:'+email;const attempt=JSON.parse(await env.SYSTEME_KV.get(key)||'{"n":0}'), emailAttempt=JSON.parse(await env.SYSTEME_KV.get(emailKey)||'{"n":0}');if(attempt.n>=5||emailAttempt.n>=5)return json({error:'Trop de tentatives. Réessayez dans 15 minutes.'},429);
  const u=await db.prepare('SELECT u.*,c.salt,c.password_hash,c.iterations FROM pdv_users u JOIN pdv_user_credentials c ON c.user_id=u.id WHERE u.email=?').bind(email).first();
  const valid=u&&u.active&&await hash(String(b.password||''),u.salt,u.iterations)===u.password_hash;
  if(!valid){await Promise.all([env.SYSTEME_KV.put(key,JSON.stringify({n:attempt.n+1}),{expirationTtl:900}),env.SYSTEME_KV.put(emailKey,JSON.stringify({n:emailAttempt.n+1}),{expirationTtl:900})]);return json({error:'Identifiants incorrects'},401);}
  await Promise.all([env.SYSTEME_KV.delete(key),env.SYSTEME_KV.delete(emailKey)]);const sid=rand(),csrf=rand();await db.prepare('INSERT INTO pdv_sessions(id,user_id,expires_at,password_version,csrf) VALUES(?,?,?,?,?)').bind(await digest(sid),u.id,Date.now()+86400000,u.password_version,csrf).run();return json({ok:true,csrf},200,{'set-cookie':sessionCookie(sid)});
 }
 const u=await auth(request,db);if(!u)return json({error:'Session requise'},401);
 if(u.company_id&&u.role!=='superadmin'){const co=await db.prepare('SELECT * FROM pdv_companies WHERE id=?').bind(u.company_id).first();if(!co||co.status==='suspended')return json({error:'Entreprise suspendue'},403);if(co.plan_expires&&Date.parse(co.plan_expires.replace(' ','T')+'Z')<Date.now()&& !['/api/me','/api/subscription-request','/api/logout'].includes(path))return json({error:'Abonnement expiré'},403);}
 if(request.method!=='GET'&&request.headers.get('x-csrf-token')!==u.csrf)return json({error:'CSRF invalide'},403);
 if(path==='/api/me'&&request.method==='GET')return json({id:u.user_id,name:u.name,email:u.email,role:u.role,company_id:u.company_id,csrf:u.csrf});
 if(path==='/api/logout'&&request.method==='POST'){await db.prepare('DELETE FROM pdv_sessions WHERE id=?').bind(await digest(cookie(request,'sid')||'')).run();return json({ok:true},200,{'set-cookie':sessionCookie('',0)});}
 if(path==='/api/overview'&&request.method==='GET'){
  const pos=await db.prepare(`SELECT p.*, (SELECT COUNT(*) FROM pdv_pos_user_assignments a WHERE a.pos_id=p.id) agents FROM pdv_points_of_sale p WHERE p.company_id=? AND (? != 'agent' OR EXISTS(SELECT 1 FROM pdv_pos_user_assignments pa WHERE pa.pos_id=p.id AND pa.user_id=?)) ORDER BY p.name`).bind(u.company_id,u.role,u.user_id).all();
  const pdv_accounts=await db.prepare(`SELECT a.*,p.name AS pos_name,s.name AS service_name FROM pdv_accounts a JOIN pdv_points_of_sale p ON p.id=a.pos_id LEFT JOIN pdv_services s ON s.id=a.service_id WHERE a.company_id=? AND (? != 'agent' OR EXISTS(SELECT 1 FROM pdv_pos_user_assignments pa WHERE pa.pos_id=a.pos_id AND pa.user_id=?)) ORDER BY p.name,a.kind`).bind(u.company_id,u.role,u.user_id).all();
  const pdv_services=await db.prepare('SELECT * FROM pdv_services WHERE company_id=?').bind(u.company_id).all();return json({pos:pos.results,pdv_accounts:pdv_accounts.results,pdv_services:pdv_services.results});
 }
 if(path==='/api/history'&&request.method==='GET'){
  const page=Math.max(0,Number(url.searchParams.get('page')||0)|0);const q=await db.prepare(`SELECT t.*,p.name AS pos_name,s.name AS service_name,u.name AS actor_name FROM pdv_transactions t JOIN pdv_points_of_sale p ON p.id=t.pos_id JOIN pdv_users u ON u.id=t.actor_id LEFT JOIN pdv_services s ON s.id=t.service_id WHERE t.company_id=? AND (? != 'agent' OR EXISTS(SELECT 1 FROM pdv_pos_user_assignments pa WHERE pa.pos_id=t.pos_id AND pa.user_id=?)) ORDER BY t.created_at DESC LIMIT 50 OFFSET ?`).bind(u.company_id,u.role,u.user_id,page*50).all();return json({rows:q.results,page});
 }
 if(path==='/api/pos'&&request.method==='POST'){
  if(u.role!=='admin')return json({error:'Administrateur requis'},403);const b=await parse(request);if(!b.name)return json({error:'Nom obligatoire'},400);const id=rand();await db.batch([db.prepare('INSERT INTO pdv_points_of_sale(id,company_id,name,city) VALUES(?,?,?,?)').bind(id,u.company_id,b.name,b.city||''),db.prepare("INSERT INTO pdv_accounts(id,company_id,pos_id,kind,balance) VALUES(?,?,?,'cash',0)").bind(rand(),u.company_id,id)]);await audit(db,u,'CREATE_POS',id);return json({ok:true});
 }
 if(path==='/api/service'&&request.method==='POST'){
  if(u.role!=='admin')return json({error:'Administrateur requis'},403);const b=await parse(request);if(!b.name)return json({error:'Nom obligatoire'},400);await db.prepare('INSERT INTO pdv_services(id,company_id,name) VALUES(?,?,?)').bind(rand(),u.company_id,b.name).run();return json({ok:true});
 }
 if(path==='/api/wallet'&&request.method==='POST'){
  if(u.role!=='admin')return json({error:'Administrateur requis'},403);const b=await parse(request);const p=await db.prepare('SELECT id FROM pdv_points_of_sale WHERE id=? AND company_id=?').bind(b.pos_id,u.company_id).first(),s=await db.prepare('SELECT id FROM pdv_services WHERE id=? AND company_id=?').bind(b.service_id,u.company_id).first();if(!p||!s)return json({error:'PDV ou service inconnu'},404);await db.prepare("INSERT OR IGNORE INTO pdv_accounts(id,company_id,pos_id,service_id,kind,balance) VALUES(?,?,?,?,'wallet',0)").bind(rand(),u.company_id,p.id,s.id).run();return json({ok:true});
 }
 if(path==='/api/movement'&&request.method==='POST'){
  const b=await parse(request),amount=Number(b.amount);
  if(!b.idempotency_key||!String(b.idempotency_key).match(/^[a-zA-Z0-9-]{20,80}$/))return json({error:'Clé idempotence requise'},400);
  const old=await db.prepare('SELECT id FROM pdv_transactions WHERE company_id=? AND idempotency_key=?').bind(u.company_id,b.idempotency_key).first();if(old)return json({ok:true,id:old.id,replayed:true});if(!Number.isSafeInteger(amount)||amount<=0)return json({error:'Montant entier positif requis'},400);
  const allowed=['deposit','withdrawal'];if(!allowed.includes(b.type))return json({error:'Type non autorisé'},400);
  if(u.role==='agent'){const assigned=await db.prepare('SELECT 1 FROM pdv_pos_user_assignments WHERE pos_id=? AND user_id=?').bind(b.pos_id,u.user_id).first();if(!assigned)return json({error:'PDV non attribué'},403);}
  const closed=await db.prepare("SELECT 1 FROM cash_closures WHERE company_id=? AND pos_id=? AND business_date=date('now') AND status='closed'").bind(u.company_id,b.pos_id).first();if(closed)return json({error:'Caisse clôturée pour aujourd’hui'},409);
  const cash=await db.prepare("SELECT * FROM pdv_accounts WHERE company_id=? AND pos_id=? AND kind='cash'").bind(u.company_id,b.pos_id).first(),wallet=await db.prepare("SELECT * FROM pdv_accounts WHERE company_id=? AND pos_id=? AND service_id=? AND kind='wallet'").bind(u.company_id,b.pos_id,b.service_id).first();if(!cash||!wallet)return json({error:'Compte ou portefeuille introuvable'},404);
  const cdelta=b.type==='deposit'?amount:-amount,wdelta=-cdelta,tx=rand();
  // Atomic conditional updates: if either account is insufficient, the entire batch is rolled back via trigger.
  await db.batch([db.prepare('INSERT INTO pdv_transactions(id,company_id,pos_id,actor_id,type,service_id,amount,note,idempotency_key) VALUES(?,?,?,?,?,?,?,?,?)').bind(tx,u.company_id,b.pos_id,u.user_id,b.type,b.service_id,amount,b.note||'',b.idempotency_key),db.prepare('UPDATE pdv_accounts SET balance=balance+? WHERE id=? AND company_id=?').bind(cdelta,cash.id,u.company_id),db.prepare('UPDATE pdv_accounts SET balance=balance+? WHERE id=? AND company_id=?').bind(wdelta,wallet.id,u.company_id),db.prepare('INSERT INTO pdv_entries(id,transaction_id,account_id,delta) VALUES(?,?,?,?)').bind(rand(),tx,cash.id,cdelta),db.prepare('INSERT INTO pdv_entries(id,transaction_id,account_id,delta) VALUES(?,?,?,?)').bind(rand(),tx,wallet.id,wdelta)]);return json({ok:true,id:tx});
 }

 if(path==='/api/pdv_users'&&request.method==='GET'){
  if(u.role!=='admin')return json({error:'Accès refusé'},403);
  const q=await db.prepare("SELECT id,name,email,role,active FROM pdv_users WHERE company_id=? ORDER BY name").bind(u.company_id).all();return json({rows:q.results});
 }
 if(path==='/api/pdv_users'&&request.method==='POST'){
  if(u.role!=='admin')return json({error:'Accès refusé'},403);
  const b=await parse(request),email=String(b.email||'').trim().toLowerCase();if(!email.includes('@')||String(b.password||'').length<12||!b.name)return json({error:'Nom, email et mot de passe fort requis'},400);
  const id=rand(),salt=rand();await db.batch([db.prepare("INSERT INTO pdv_users(id,company_id,name,email,role) VALUES(?,?,?,?,'agent')").bind(id,u.company_id,b.name,email),db.prepare('INSERT INTO pdv_user_credentials(user_id,salt,password_hash) VALUES(?,?,?)').bind(id,salt,await hash(b.password,salt))]);await audit(db,u,'CREATE_AGENT',id);return json({ok:true});
 }
 if(path==='/api/assign'&&request.method==='POST'){
  if(u.role!=='admin')return json({error:'Accès refusé'},403);const b=await parse(request);
  const p=await db.prepare('SELECT id FROM pdv_points_of_sale WHERE id=? AND company_id=?').bind(b.pos_id,u.company_id).first(),a=await db.prepare("SELECT id FROM pdv_users WHERE id=? AND company_id=? AND role='agent' AND active=1").bind(b.user_id,u.company_id).first();if(!p||!a)return json({error:'PDV ou agent invalide'},400);
  await db.prepare('INSERT OR IGNORE INTO pdv_pos_user_assignments(pos_id,user_id) VALUES(?,?)').bind(p.id,a.id).run();await audit(db,u,'ASSIGN_AGENT',p.id+':'+a.id);return json({ok:true});
 }
 if(path==='/api/initial-funds'&&request.method==='POST'){
  if(u.role!=='admin')return json({error:'Accès refusé'},403);const b=await parse(request),amount=Number(b.amount);if(!Number.isSafeInteger(amount)||amount<=0)return json({error:'Montant invalide'},400);
  const a=await db.prepare('SELECT * FROM pdv_accounts WHERE id=? AND company_id=?').bind(b.account_id,u.company_id).first();if(!a)return json({error:'Compte invalide'},404);
  const tx=rand(),key=String(b.idempotency_key||'');if(!/^[a-zA-Z0-9-]{20,80}$/.test(key))return json({error:'Clé idempotence requise'},400);
  const old=await db.prepare('SELECT id FROM pdv_transactions WHERE company_id=? AND idempotency_key=?').bind(u.company_id,key).first();if(old)return json({ok:true,id:old.id,replayed:true});
  await db.batch([db.prepare('INSERT INTO pdv_transactions(id,company_id,pos_id,actor_id,type,service_id,amount,note,idempotency_key) VALUES(?,?,?,?,?,?,?,?,?)').bind(tx,u.company_id,a.pos_id,u.user_id,'funding',a.service_id,amount,String(b.note||'Approvisionnement'),key),db.prepare('UPDATE pdv_accounts SET balance=balance+? WHERE id=? AND company_id=?').bind(amount,a.id,u.company_id),db.prepare('INSERT INTO pdv_entries(id,transaction_id,account_id,delta) VALUES(?,?,?,?)').bind(rand(),tx,a.id,amount)]);await audit(db,u,'FUND_ACCOUNT',tx);return json({ok:true,id:tx});
 }
 if(path==='/api/audit'&&request.method==='GET'){
  if(u.role!=='admin'&&u.role!=='superadmin')return json({error:'Accès refusé'},403);
  const q=await db.prepare('SELECT action,detail,created_at FROM pdv_audit_logs WHERE company_id=? ORDER BY created_at DESC LIMIT 100').bind(u.company_id).all();return json({rows:q.results});
 }
 if(path==='/api/subscription-request'&&request.method==='POST'){
  if(u.role!=='admin')return json({error:'Administrateur requis'},403);const b=await parse(request);if(!['standard','business','ultimate'].includes(b.plan)||!b.transaction_id||!b.phone)return json({error:'Informations manquantes'},400);
  const company=await db.prepare('SELECT plan,plan_expires FROM pdv_companies WHERE id=?').bind(u.company_id).first();if(company.plan!=='free'&&(!company.plan_expires||Date.parse(company.plan_expires.replace(' ','T')+'Z')>Date.now()))return json({error:'Abonnement actif'},409);
  const pending=await db.prepare("SELECT id FROM pdv_subscription_requests WHERE company_id=? AND status='pending'").bind(u.company_id).first();if(pending)return json({error:'Demande déjà en attente'},409);
  await db.prepare('INSERT INTO pdv_subscription_requests(id,company_id,plan,phone,transaction_id) VALUES(?,?,?,?,?)').bind(rand(),u.company_id,b.plan,b.phone,b.transaction_id).run();await audit(db,u,'SUBSCRIPTION_REQUEST',b.plan);return json({ok:true});
 }
 if(path==='/api/super/pdv_companies'&&request.method==='GET'){
  if(u.role!=='superadmin')return json({error:'Accès refusé'},403);const q=await db.prepare('SELECT id,name,email,plan,plan_expires,status FROM pdv_companies ORDER BY created_at DESC LIMIT 200').all();return json({rows:q.results});
 }
 if(path==='/api/super/subscriptions'&&request.method==='GET'){
  if(u.role!=='superadmin')return json({error:'Accès refusé'},403);const q=await db.prepare("SELECT r.*,c.name AS company_name FROM pdv_subscription_requests r JOIN pdv_companies c ON c.id=r.company_id ORDER BY r.created_at DESC LIMIT 200").all();return json({rows:q.results});
 }
 if(path==='/api/super/subscription-decision'&&request.method==='POST'){
  if(u.role!=='superadmin')return json({error:'Accès refusé'},403);const b=await parse(request);if(!['approved','rejected'].includes(b.decision))return json({error:'Décision invalide'},400);
  const r=await db.prepare("SELECT * FROM pdv_subscription_requests WHERE id=? AND status='pending'").bind(b.id).first();if(!r)return json({error:'Demande introuvable'},404);
  const days={standard:30,business:365};const expiry=r.plan==='ultimate'?null:new Date(Date.now()+days[r.plan]*86400000).toISOString();
  const statements=[db.prepare("UPDATE pdv_subscription_requests SET status=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'").bind(b.decision,r.id)];
  if(b.decision==='approved')statements.push(db.prepare('UPDATE pdv_companies SET plan=?,plan_expires=? WHERE id=?').bind(r.plan,expiry,r.company_id));
  await db.batch(statements);await audit(db,u,'SUBSCRIPTION_DECISION',r.id+':'+b.decision);return json({ok:true});
 }

 if(path==='/api/cash/close'&&request.method==='POST'){
  const b=await parse(request),pos=String(b.pos_id||'');
  const permitted=await db.prepare("SELECT p.id FROM pdv_points_of_sale p WHERE p.id=? AND p.company_id=? AND p.active=1 AND (?='admin' OR EXISTS(SELECT 1 FROM pdv_pos_user_assignments a WHERE a.pos_id=p.id AND a.user_id=?))").bind(pos,u.company_id,u.role,u.user_id).first();
  if(!permitted)return json({error:'PDV non autorisé'},403);
  const observed=b.observed;if(!observed||typeof observed!=='object'||Array.isArray(observed))return json({error:'Montants constatés requis'},400);
  const pdv_accounts=(await db.prepare('SELECT id,balance,kind FROM pdv_accounts WHERE company_id=? AND pos_id=? ORDER BY id').bind(u.company_id,pos).all()).results;
  if(pdv_accounts.length===0||Object.keys(observed).length!==pdv_accounts.length)return json({error:'Déclarer tous les comptes du PDV'},400);
  const rows=[];for(const a of pdv_accounts){const n=Number(observed[a.id]);if(!Number.isSafeInteger(n)||n<0)return json({error:'Montant constaté invalide'},400);rows.push({id:a.id,expected:a.balance,observed:n,difference:n-a.balance});}
  const id=rand(),today=new Date().toISOString().slice(0,10);
  try{await db.batch([db.prepare("INSERT INTO cash_closures(id,company_id,pos_id,business_date,actor_id,status,observations) VALUES(?,?,?,?,?,'closed',?)").bind(id,u.company_id,pos,today,u.user_id,String(b.note||'').slice(0,1000)),...rows.map(a=>db.prepare('INSERT INTO cash_closure_lines(id,closure_id,account_id,expected,observed,difference) VALUES(?,?,?,?,?,?)').bind(rand(),id,a.id,a.expected,a.observed,a.difference)),db.prepare('INSERT INTO pdv_audit_logs(id,company_id,user_id,action,detail) VALUES(?,?,?,?,?)').bind(rand(),u.company_id,u.user_id,'CASH_CLOSE',id)]);}catch(e){if(String(e).includes('UNIQUE'))return json({error:'PDV déjà clôturé aujourd’hui'},409);throw e;}
  return json({ok:true,id,rows});
 }
 if(path==='/api/cash/closures'&&request.method==='GET'){
  const q=await db.prepare("SELECT c.id,c.business_date,c.status,c.created_at,p.name AS pos_name,c.observations FROM cash_closures c JOIN pdv_points_of_sale p ON p.id=c.pos_id WHERE c.company_id=? AND (?='admin' OR EXISTS(SELECT 1 FROM pdv_pos_user_assignments a WHERE a.pos_id=c.pos_id AND a.user_id=?)) ORDER BY c.created_at DESC LIMIT 100").bind(u.company_id,u.role,u.user_id).all();return json({rows:q.results});
 }
 if(path==='/api/corrections'&&request.method==='POST'){
  const b=await parse(request),reason=String(b.reason||'').trim();if(reason.length<8)return json({error:'Justification de 8 caractères minimum'},400);
  const tx=await db.prepare("SELECT t.id,t.pos_id,t.type,t.amount,t.company_id FROM pdv_transactions t WHERE t.id=? AND t.company_id=? AND (?='admin' OR EXISTS(SELECT 1 FROM pdv_pos_user_assignments a WHERE a.pos_id=t.pos_id AND a.user_id=?))").bind(b.transaction_id,u.company_id,u.role,u.user_id).first();if(!tx)return json({error:'Mouvement non autorisé'},404);
  const existing=await db.prepare("SELECT id FROM pdv_correction_requests WHERE transaction_id=? AND status IN ('pending','approved')").bind(tx.id).first();if(existing)return json({error:'Correction déjà demandée ou effectuée'},409);
  const id=rand();await db.prepare("INSERT INTO pdv_correction_requests(id,company_id,transaction_id,requester_id,reason,status) VALUES(?,?,?,?,?,'pending')").bind(id,u.company_id,tx.id,u.user_id,reason).run();await audit(db,u,'CORRECTION_REQUEST',id);return json({ok:true,id});
 }
 if(path==='/api/corrections'&&request.method==='GET'){
  const q=await db.prepare("SELECT r.id,r.transaction_id,r.reason,r.status,r.created_at,t.amount,t.type,t.pos_id FROM pdv_correction_requests r JOIN pdv_transactions t ON t.id=r.transaction_id WHERE r.company_id=? AND (?='admin' OR EXISTS(SELECT 1 FROM pdv_pos_user_assignments a WHERE a.pos_id=t.pos_id AND a.user_id=?)) ORDER BY r.created_at DESC LIMIT 100").bind(u.company_id,u.role,u.user_id).all();return json({rows:q.results});
 }
 if(path==='/api/corrections/decide'&&request.method==='POST'){
  if(u.role!=='admin')return json({error:'Administrateur requis'},403);
  const b=await parse(request);if(!['approved','rejected'].includes(b.decision))return json({error:'Décision invalide'},400);
  const cred=await db.prepare('SELECT salt,password_hash,iterations FROM pdv_user_credentials WHERE user_id=?').bind(u.user_id).first();
  if(!cred||await hash(String(b.password||''),cred.salt,cred.iterations)!==cred.password_hash)return json({error:'Mot de passe administrateur incorrect'},403);
  const req=await db.prepare("SELECT r.*,t.pos_id,t.type,t.amount,t.service_id FROM pdv_correction_requests r JOIN pdv_transactions t ON t.id=r.transaction_id WHERE r.id=? AND r.company_id=? AND r.status='pending'").bind(b.id,u.company_id).first();if(!req)return json({error:'Demande introuvable ou déjà traitée'},404);
  if(b.decision==='rejected'){
   await db.batch([db.prepare("UPDATE pdv_correction_requests SET status='rejected',approver_id=?,decided_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'").bind(u.user_id,req.id),db.prepare('INSERT INTO pdv_audit_logs(id,company_id,user_id,action,detail) VALUES(?,?,?,?,?)').bind(rand(),u.company_id,u.user_id,'CORRECTION_REJECT',req.id)]);return json({ok:true});
  }
  const original=(await db.prepare('SELECT account_id,delta FROM pdv_entries WHERE transaction_id=?').bind(req.transaction_id).all()).results;
  if(!original.length)return json({error:'Écritures initiales absentes'},409);
  const id=rand(),key='correction-'+req.id;
  const batch=[db.prepare("INSERT INTO pdv_transactions(id,company_id,pos_id,actor_id,type,service_id,amount,note,idempotency_key) VALUES(?,?,?,?,? ,?,?,?,?)").bind(id,u.company_id,req.pos_id,u.user_id,'reversal',req.service_id,req.amount,'Contre-écriture: '+req.reason,key)];
  for(const e of original){batch.push(db.prepare('UPDATE pdv_accounts SET balance=balance-? WHERE id=? AND company_id=?').bind(e.delta,e.account_id,u.company_id));batch.push(db.prepare('INSERT INTO pdv_entries(id,transaction_id,account_id,delta) VALUES(?,?,?,?)').bind(rand(),id,e.account_id,-e.delta));}
  batch.push(db.prepare("UPDATE pdv_correction_requests SET status='approved',approver_id=?,reversal_transaction_id=?,decided_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'").bind(u.user_id,id,req.id));
  batch.push(db.prepare('INSERT INTO pdv_audit_logs(id,company_id,user_id,action,detail) VALUES(?,?,?,?,?)').bind(rand(),u.company_id,u.user_id,'CORRECTION_APPROVE',req.id+':'+id));
  try{await db.batch(batch)}catch(e){if(String(e).includes('Fonds insuffisants'))return json({error:'Contre-écriture impossible : fonds insuffisants. Réapprovisionner ou effectuer une régularisation contrôlée.'},409);throw e;}
  return json({ok:true,reversal_transaction_id:id});
 }
 if(path==='/api/password/change'&&request.method==='POST'){
  const b=await parse(request),pwd=String(b.new_password||'');if(pwd.length<12||pwd.length>256)return json({error:'Nouveau mot de passe : 12 à 256 caractères'},400);
  const c=await db.prepare('SELECT * FROM pdv_user_credentials WHERE user_id=?').bind(u.user_id).first();if(!c||await hash(String(b.old_password||''),c.salt,c.iterations)!==c.password_hash)return json({error:'Mot de passe actuel incorrect'},403);
  const salt=rand();await db.batch([db.prepare('UPDATE pdv_user_credentials SET salt=?,password_hash=?,iterations=210000 WHERE user_id=?').bind(salt,await hash(pwd,salt),u.user_id),db.prepare('UPDATE pdv_users SET password_version=password_version+1 WHERE id=?').bind(u.user_id),db.prepare('DELETE FROM pdv_sessions WHERE user_id=?').bind(u.user_id),db.prepare('INSERT INTO pdv_audit_logs(id,company_id,user_id,action,detail) VALUES(?,?,?,?,?)').bind(rand(),u.company_id,u.user_id,'PASSWORD_CHANGE','')]);return json({ok:true,relogin:true},200,{'set-cookie':sessionCookie('',0)});
 }
 if(path==='/api/password/reset-user'&&request.method==='POST'){
  if(!['admin','superadmin'].includes(u.role))return json({error:'Accès refusé'},403);
  const b=await parse(request),pwd=String(b.new_password||'');if(pwd.length<12||pwd.length>256)return json({error:'Mot de passe trop court ou trop long'},400);
  const c=await db.prepare('SELECT * FROM pdv_user_credentials WHERE user_id=?').bind(u.user_id).first();if(!c||await hash(String(b.admin_password||''),c.salt,c.iterations)!==c.password_hash)return json({error:'Mot de passe du responsable incorrect'},403);
  const target=await db.prepare('SELECT id,role,company_id FROM pdv_users WHERE id=? AND active=1').bind(b.user_id).first();if(!target||(u.role==='admin'&&(target.company_id!==u.company_id||target.role!=='agent'))||(u.role==='superadmin'&&target.role!=='admin'))return json({error:'Utilisateur non autorisé'},403);
  const salt=rand();await db.batch([db.prepare('UPDATE pdv_user_credentials SET salt=?,password_hash=?,iterations=210000 WHERE user_id=?').bind(salt,await hash(pwd,salt),target.id),db.prepare('UPDATE pdv_users SET password_version=password_version+1 WHERE id=?').bind(target.id),db.prepare('DELETE FROM pdv_sessions WHERE user_id=?').bind(target.id),db.prepare('INSERT INTO pdv_audit_logs(id,company_id,user_id,action,detail) VALUES(?,?,?,?,?)').bind(rand(),target.company_id,u.user_id,'PASSWORD_RESET',target.id)]);return json({ok:true});
 }
 if(path==='/api/report'&&request.method==='GET'){
  const pos=url.searchParams.get('pos_id'),start=url.searchParams.get('start'),end=url.searchParams.get('end');
  if(!/^\d{4}-\d{2}-\d{2}$/.test(start||'')||!/^\d{4}-\d{2}-\d{2}$/.test(end||'')||start>end)return json({error:'Dates invalides'},400);
  const q=await db.prepare("SELECT t.id,t.created_at,t.type,t.amount,t.note,p.name AS pos_name,s.name AS service_name,us.name AS actor_name FROM pdv_transactions t JOIN pdv_points_of_sale p ON p.id=t.pos_id JOIN pdv_users us ON us.id=t.actor_id LEFT JOIN pdv_services s ON s.id=t.service_id WHERE t.company_id=? AND date(t.created_at)>=? AND date(t.created_at)<=? AND (? IS NULL OR t.pos_id=?) AND (?='admin' OR EXISTS(SELECT 1 FROM pdv_pos_user_assignments a WHERE a.pos_id=t.pos_id AND a.user_id=?)) ORDER BY t.created_at,t.id LIMIT 5000").bind(u.company_id,start,end,pos,pos,u.role,u.user_id).all();
  const company=await db.prepare('SELECT name,phone,city FROM pdv_companies WHERE id=?').bind(u.company_id).first();return json({company,rows:q.results,start,end,limited:q.results.length===5000,generated_at:new Date().toISOString()});
 }

 return json({error:'Route inconnue'},404);
 }catch(e){console.error('API error',path,String(e));return json({error:'Erreur serveur. Vérifiez les journaux Cloudflare.'},500)}
 }};
