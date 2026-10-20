// Disposable PostgreSQL (PGlite). Never connects to a live Supabase project.
// Dependency: @electric-sql/pglite@0.3.14; run via NODE_PATH or install locally without saving.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {PGlite} = require('@electric-sql/pglite');
const read = name => fs.readFileSync(path.join(__dirname, '../supabase', name), 'utf8');
const files = ['schema.sql', 'schema_v4_legacy.sql', 'migrate_v4_to_v4_1.sql', 'migrate_add_interview_schedules.sql'];
const privileges = {
  profiles: ['SELECT','UPDATE'], employees: ['SELECT','INSERT','UPDATE','DELETE'],
  goals: ['SELECT','INSERT','UPDATE','DELETE'], interviews: ['SELECT','INSERT','UPDATE','DELETE'],
  audit_logs: ['SELECT','INSERT'], interview_schedules: ['SELECT','INSERT','UPDATE','DELETE']
};
const A='00000000-0000-0000-0000-000000000001', B='00000000-0000-0000-0000-000000000002';
const E='00000000-0000-0000-0000-000000000011', F='00000000-0000-0000-0000-000000000012';
async function setup(db, oldDefaults) {
  await db.exec(`create role anon; create role authenticated; create role service_role bypassrls;
    grant usage on schema public to anon, authenticated, service_role;
    create schema auth; create table auth.users(id uuid primary key, email text, raw_user_meta_data jsonb default '{}');
    create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('test.uid',true),'')::uuid $$;
    grant usage on schema auth to authenticated;
    grant execute on function auth.uid() to authenticated;
    alter default privileges in schema public revoke execute on functions from public;`);
  if(oldDefaults) await db.exec(`alter default privileges in schema public grant all on tables to anon,authenticated,service_role;`);
}
// pgcrypto is not bundled in this WASM runtime; gen_random_uuid() is built in.
async function apply(db, name) {await db.exec(read(name).replace(/create extension if not exists "pgcrypto";/i,''));}
async function checkAcl(db) {
  for(const [table, expected] of Object.entries(privileges)) {
    for(const role of ['anon','authenticated','service_role']) {
      for(const privilege of ['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) {
        const {rows}=await db.query('select has_table_privilege($1,$2,$3) as allowed',[role,'public.'+table,privilege]);
        assert.equal(rows[0].allowed, role==='authenticated' && expected.includes(privilege), `${role} ${table} ${privilege}`);
      }
    }
    assert.equal((await db.query(`select relrowsecurity from pg_class where oid=$1::regclass`,['public.'+table])).rows[0].relrowsecurity,true);
  }
}
async function denied(db, sql, code='42501') {await assert.rejects(db.exec(sql),e=>e.code===code);}
async function behavior(db) {
  await db.exec(`insert into auth.users(id,email) values('${A}','a@example.test'),('${B}','b@example.test');
    update profiles set account_status='active',role='manager';
    insert into employees(id,name,manager_id) values('${E}','A employee','${A}'),('${F}','B employee','${B}');
    set role authenticated; set test.uid='${A}';`);
  // Authenticated profile read works, but registration belongs to the auth trigger.
  assert.equal((await db.query('select * from profiles')).rows.length,1);
  await denied(db,`insert into profiles(id,name) values(gen_random_uuid(),'not allowed')`);
  assert.equal((await db.query('select * from employees')).rows.length,1);
  await denied(db,`insert into employees(name,manager_id) values('wrong owner','${B}')`);
  await db.exec(`insert into goals(title,owner_id,created_by) values('own goal','${E}','${A}');
    update goals set progress=10 where owner_id='${E}';
    insert into interviews(employee_id,manager_id,interview_date,summary) values('${E}','${A}',current_date,'test');
    insert into interview_schedules(employee_id,manager_id,scheduled_date) values('${E}','${A}',current_date);
    update interview_schedules set status='완료' where employee_id='${E}';
    insert into audit_logs(actor_id,action,target_type) values('${A}','test','test');`);
  // Identity-generated audit IDs work without expanding sequence privileges.
  await denied(db,`update audit_logs set action='tampered'`);
  await denied(db,`delete from audit_logs`);
  assert.equal((await db.query('select * from audit_logs')).rows.length,0); // admin-only read
  await db.exec(`set test.uid='${B}';`);
  assert.equal((await db.query('select * from goals')).rows.length,0);
  assert.equal((await db.query('select * from interview_schedules')).rows.length,0);
  await db.exec(`set test.uid='${A}'; delete from interview_schedules; delete from interviews; delete from goals;
    reset role; set role anon;`);
  for(const table of Object.keys(privileges)) await denied(db,`select * from public.${table}`);
  await db.exec('reset role; set role service_role;');
  for(const table of Object.keys(privileges)) await denied(db,`select * from public.${table}`);
  await db.exec(`reset role; update profiles set role='admin' where id='${A}'; set role authenticated; set test.uid='${A}';`);
  assert.equal((await db.query('select * from audit_logs')).rows.length,1);
  await db.exec(`update profiles set name='approved' where id='${B}';`);
  await db.exec('reset role;');
}
async function existingAclUnchanged(db) {
  // Exercise every actual creation block on existing tables with unusual ACLs.
  await db.exec(`grant select on profiles to anon; revoke update on profiles from authenticated;`);
  const snapshot=async()=>JSON.stringify((await db.query(`select relname,relacl::text from pg_class where relnamespace='public'::regnamespace order by relname`)).rows);
  const before=await snapshot();
  for(const name of files) for(const m of read(name).matchAll(/do \$table_setup\$[\s\S]*?\$table_setup\$;/g)) await db.exec(m[0]);
  assert.equal(await snapshot(),before,'Existing table ACLs must remain exactly unchanged');
}
(async()=>{
  for(const oldDefaults of [false,true]) for(const legacy of [false,true]) {
    const db=new PGlite();
    try {
      await setup(db,oldDefaults);
      if(legacy) {await apply(db,'schema_v4_legacy.sql');await apply(db,'migrate_v4_to_v4_1.sql');}
      else await apply(db,'schema.sql');
      await apply(db,'migrate_add_interview_schedules.sql');
      await checkAcl(db); await behavior(db); await existingAclUnchanged(db);
      console.log(`PASS: ${legacy?'V4→V4.1 migration':'fresh V4.1'}, ${oldDefaults?'legacy automatic grants':'opt-in defaults'}; ACL/RLS/CRUD/identity/existing ACL preservation`);
    } finally {await db.close();}
  }
})().catch(e=>{console.error(e);process.exitCode=1;});
