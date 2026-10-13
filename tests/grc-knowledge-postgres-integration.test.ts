import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import {initUsers,beginRegistration} from '../src/user-auth.js';
import {initOrganizations,createOrganization} from '../src/grc-organizations.js';
import {initControlRegistry} from '../src/grc-controls.js';
import {
 initKnowledgeSources,registerKnowledgeSource,reviewKnowledgeSource,
 createKnowledgeItem,verifyKnowledgeItem,createAssessmentPack,
 addKnowledgeToAssessmentPack,reviewAssessmentPack,requireUsableAssessmentPack
} from '../src/grc-knowledge-sources.js';

const ciDb=process.env.NODE_ENV==='test'&&/^postgres(?:ql)?:\/\/[^/]*@(?:localhost|127\.0\.0\.1):5432\//.test(process.env.DATABASE_URL||'');

test('real PostgreSQL knowledge review and assessment-pack lifecycle fails closed when knowledge becomes stale',{skip:!ciDb,timeout:30000},async()=>{
 const pool=new pg.Pool({connectionString:process.env.DATABASE_URL,ssl:false});
 let creator:string|undefined,reviewer:string|undefined;
 let orgId:string|undefined;
 try{
  await initUsers();await initOrganizations();await initControlRegistry();await initKnowledgeSources();
  const suffix=crypto.randomUUID(),password='Aegis-Knowledge-'+crypto.randomBytes(10).toString('hex');
  const creatorRegistration=await beginRegistration(`knowledge-creator-${suffix}@example.test`,password,{fullName:'Knowledge Creator'});
  const reviewerRegistration=await beginRegistration(`knowledge-reviewer-${suffix}@example.test`,password,{fullName:'Independent Reviewer'});
  creator=creatorRegistration.userId;reviewer=reviewerRegistration.userId;
  const org=await createOrganization(creator,{name:`Knowledge lifecycle ${crypto.randomUUID()}`});orgId=org.id;
  await pool.query("INSERT INTO grc_organization_members(organization_id,user_id,role) VALUES($1,$2,'REVIEWER')",[org.id,reviewer]);

  const source=await registerKnowledgeSource(creator,org.id,{
   sha256:crypto.createHash('sha256').update(crypto.randomBytes(32)).digest('hex'),
   title:'CI reviewed knowledge source',sourceType:'PDF',authorityClass:'IMPLEMENTATION_AID'
  });
  const item=await createKnowledgeItem(creator,org.id,source.id,{
   itemKey:'CI-EVIDENCE-1',itemType:'EVIDENCE_EXPECTATION',title:'CI evidence expectation',
   content:'Collect organization-specific evidence and retain independent review.'
  });
  await assert.rejects(()=>verifyKnowledgeItem(reviewer,org.id,item.id,'VERIFIED'),/Source must be reviewed/);
  await reviewKnowledgeSource(reviewer,org.id,source.id,'REVIEWED');
  const verified=await verifyKnowledgeItem(reviewer,org.id,item.id,'VERIFIED');
  assert.equal(verified.review_status,'VERIFIED');

  const pack=await createAssessmentPack(creator,org.id,{packKey:'CI-READINESS',title:'CI Readiness Pack'});
  await addKnowledgeToAssessmentPack(creator,org.id,pack.id,item.id,10);
  await assert.rejects(()=>reviewAssessmentPack(creator,org.id,pack.id),/Independent assessment pack reviewer required/);
  const reviewed=await reviewAssessmentPack(reviewer,org.id,pack.id);
  assert.equal(reviewed.status,'REVIEWED');
  const usable=await requireUsableAssessmentPack(reviewer,org.id,pack.id);
  assert.equal(usable.knowledge_health,'VALID');
  assert.equal(usable.valid_item_count,1);

  await pool.query("UPDATE grc_knowledge_items SET review_status='REJECTED',verified_by=$2,verified_at=now() WHERE id=$1",[item.id,reviewer]);
  await assert.rejects(()=>requireUsableAssessmentPack(reviewer,org.id,pack.id),/stale and must be re-reviewed before use/);
 }finally{
  if(orgId)await pool.query('DELETE FROM grc_organizations WHERE id=$1',[orgId]).catch(()=>{});
  if(creator&&reviewer)await pool.query('DELETE FROM app_users WHERE id=ANY($1::uuid[])',[[creator,reviewer]]).catch(()=>{});
  await pool.end();
 }
});
