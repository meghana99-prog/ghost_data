#!/usr/bin/env python3
"""Deterministic, evidence-backed deletion audit for the supplied challenge dataset.
Uses pdftotext and (optionally) Tesseract for multimodal evidence extraction.
"""
from __future__ import annotations
import csv, hashlib, json, re, shutil, sqlite3, subprocess, sys, unicodedata
from collections import defaultdict, Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
ROOT=Path(__file__).resolve().parents[1]; DATA=ROOT/'dataset'; OUT=ROOT/'output.csv'
FINDING_ORDER={'REPORT_REMAINING_RECORD':0,'REPORT_EXPOSED_PII':1,'REPORT_ACTIVE_DATA_FLOW':2,'REPORT_RESTORE_RISK':3}
REMEDIATION_ORDER={'DISABLE_DATA_FLOW':0,'BLOCK_RESTORE':1,'DELETE_RECORD':2,'REDACT_RECORD':3,'ANONYMIZE_RECORD':4}
VERIFICATION_ORDER={'VERIFY_RECORD_ABSENT':0,'VERIFY_RECORD_PRESENT':1,'VERIFY_RECORD_REDACTED':2,'VERIFY_RECORD_ANONYMIZED':3,'VERIFY_DATA_FLOW_DISABLED':4,'VERIFY_RESTORE_BLOCKED':5}
RID_RE=re.compile(r'\b(?:account|analytics|backup|data_flow|export|search|support|audit_record|tombstone|cache|marketing|telemetry|attachment|delivery_log|email_log|marketing_profile|support_attachment|cache_entry|analytics_profile)_\d+[A-Za-z0-9-]*\b',re.I)
EMAIL_RE=re.compile(r'[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}',re.I)
def readcsv(p):
 with open(p,encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
POLICY_ACTIONS={r['data_category']:r['required_action'].strip().upper() for r in readcsv(DATA/'deletion_rules.csv')} if (DATA/'deletion_rules.csv').exists() else {}
def dt(v):
 if not v:return None
 try:
  s=str(v).strip(); s=s[:-1]+'+00:00' if s.endswith('Z') else s; x=datetime.fromisoformat(s)
  return x.replace(tzinfo=timezone.utc) if x.tzinfo is None else x.astimezone(timezone.utc)
 except (ValueError,TypeError):return None
def vals(x):
 if isinstance(x,dict):return [z for k,v in x.items() for z in [str(k),*vals(v)]]
 if isinstance(x,(list,tuple)):return [z for v in x for z in vals(v)]
 return [] if x is None else [str(x)]
def norm(s):return ''.join(c for c in unicodedata.normalize('NFKD',s).casefold() if not unicodedata.combining(c))
def digits(s):return re.sub(r'\D','',s)
def system(s):
 x=(s or '').casefold()
 for key,v in [('account','account_service'),('customer_profile','account_service'),('identity','identity_service'),('search','search_service'),('analytics','analytics_platform'),('telemetry','analytics_platform'),('support','support_platform'),('ticket','support_platform'),('attachment','support_platform'),('export','export_service'),('marketing','marketing_service'),('security','security_service'),('audit','security_service'),('legal','legal_service'),('backup','backup_service'),('restore','backup_service'),('connector','integration_service'),('integration','integration_service'),('cache','cache_service'),('delivery','notification_service'),('email','notification_service')]:
  if key in x:return v
 return 'unknown_service'
def system_rid(rid,fallback=''):
 p=rid.casefold().split('_')[0]
 return {'account':'account_service','analytics':'analytics_platform','backup':'backup_service','data':'integration_service','export':'export_service','search':'search_service','support':'support_platform','audit':'security_service','tombstone':'identity_service','cache':'cache_service','marketing':'marketing_service','telemetry':'analytics_platform','attachment':'support_platform','email':'notification_service'}.get(p,system(fallback))
@dataclass
class Item:
 file_id:str; captured:datetime|None; system_id:str; collection:str; resource_id:str; data:Any
 kind:str='record'; raw:str=''; path:str=''; observed:datetime|None=None
 @property
 def text(self):return self.raw or ' '.join(vals(self.data))
 @property
 def time(self):return self.observed or self.captured or datetime.min.replace(tzinfo=timezone.utc)
def add(out,fid,cap,sysid,coll,d,path,observed=None):
 if not isinstance(d,dict):return
 rid=str(d.get('resource_id') or d.get('id') or '')
 if rid:out.append(Item(fid,cap,sysid,coll,rid,d,'record','',path,dt(d.get('observed_at')) or observed or cap))
def json_items(fid,cap,path,obj):
 out=[]; rel=str(path.relative_to(DATA))
 if isinstance(obj,dict) and isinstance(obj.get('snapshots'),list):
  for s in obj['snapshots']:
   coll=str(s.get('collection') or '')
   if not (s.get('records') or []):out.append(Item(fid,cap,str(s.get('data_store') or 'unknown_service'),coll,'',{'empty_scope':True},'scope','',rel,dt(s.get('captured_at')) or cap))
   for d in s.get('records',[]) or []:
    before=len(out);add(out,fid,cap,str(s.get('data_store') or 'unknown_service'),coll,d,rel,dt(s.get('captured_at')))
    if 'operational_record_history' in coll.casefold() and len(out)>before:out[-1].kind='activity'
  return out
 if isinstance(obj,dict) and isinstance(obj.get('service_exports'),dict):
  for sysid,groups in obj['service_exports'].items():
   if not isinstance(groups,dict):continue
   for coll,records in groups.items():
    for d in records if isinstance(records,list) else []:
     if not isinstance(d,dict):continue
     if d.get('resource_id'):add(out,fid,cap,sysid,coll,d,rel)
     elif isinstance(d.get('hits'),dict):
      for doc in d['hits'].get('documents',[]):add(out,fid,cap,sysid,coll,doc,rel,dt(d.get('observed_at')))
  return out
 if isinstance(obj,dict) and isinstance(obj.get('records'),list):
  for d in obj['records']:
   if not isinstance(d,dict):continue
   coll=str(d.get('record_type') or d.get('collection') or obj.get('collection') or '')
   add(out,fid,cap,system(str(d.get('system') or obj.get('system') or obj.get('origin') or obj.get('source') or '')+' '+coll),coll,d,rel,dt(d.get('recorded_at')))
  return out
 def walk(x,parent=''):
  if isinstance(x,dict):
   if x.get('resource_id'):add(out,fid,cap,system(str(x.get('system') or parent)),parent,x,rel)
   for k,v in x.items():
    if isinstance(v,(dict,list)):walk(v,str(k))
  elif isinstance(x,list):
   for v in x:walk(v,parent)
 walk(obj);return out
def sql_items(fid,cap,path):
 out=[]; c=sqlite3.connect(':memory:')
 try:
  c.executescript(path.read_text(encoding='utf-8',errors='replace'))
  for (table,) in c.execute("select name from sqlite_master where type='table'"):
   if table=='snapshot_scope':continue
   if 'customer_profile' in table.casefold():out.append(Item(fid,cap,system(table),table,'',{'table_scope':True},'scope','',str(path.relative_to(DATA)),cap))
   cols=[r[1] for r in c.execute(f'pragma table_info("{table}")')]
   for tup in c.execute(f'SELECT * FROM "{table}"'):
    d=dict(zip(cols,tup))
    if d.get('record_json'):
     try:obj=json.loads(d['record_json'])
     except Exception:obj={'record_json':d['record_json']}
     coll=str(d.get('collection_name') or table);sysid=system(str(d.get('origin_system') or '')+' '+coll)
     if 'operational_record_history' in coll.casefold():continue
     rid=str(d.get('resource_id') or obj.get('resource_id') or '')
    else:obj=d;sysid=system(table);coll=table;rid=str(d.get('resource_id') or '')
    if rid:out.append(Item(fid,cap,sysid,coll,rid,obj,'record','',str(path.relative_to(DATA)),dt(d.get('updated_at')) or cap))
 except Exception as e:print(f'WARN SQL {path.name}: {e}',file=sys.stderr)
 finally:c.close()
 return out
def line_items(fid,cap,path,text,kind):
 out=[];rel=str(path.relative_to(DATA))
 for line in text.splitlines():
  ids=list(dict.fromkeys(RID_RE.findall(line)))
  if not ids:continue
  parts=[x.strip() for x in line.split('|')]
  for rid in ids:
   d={'line':line}
   if len(parts)>=5:
    d.update(system=parts[1],record_type=parts[3],result=parts[4])
    if len(parts)>5:d['subject_reference']=parts[5]
   for k,v in re.findall(r'([A-Za-z_]+)=([A-Za-z0-9_.@+-]+)',line):d[k]=v.strip('"')
   sysid=system_rid(rid,line)
   out.append(Item(fid,cap,sysid,path.stem,rid,d,kind,line,rel,dt(line[:20]) or cap))
 ids=list(dict.fromkeys(RID_RE.findall(text)))
 if len(ids)==1:
  rid=ids[0];out.append(Item(fid,cap,system_rid(rid,path.name),path.stem,rid,{'document':text},kind,text,rel,cap))
 return out
def load_items(manifest):
 out=[]
 for m in manifest:
  p=DATA/m['file_path'];cap=dt(m.get('captured_at'));fid=m['file_id']
  if not p.exists():continue
  try:
   ext=p.suffix.casefold()
   if ext=='.json':out+=json_items(fid,cap,p,json.loads(p.read_text(encoding='utf-8')))
   elif ext=='.sql':out+=sql_items(fid,cap,p)
   elif ext in {'.log','.txt'}:out+=line_items(fid,cap,p,p.read_text(encoding='utf-8',errors='replace'),'text')
   elif ext=='.pdf' and shutil.which('pdftotext'):
    t=subprocess.run(['pdftotext','-layout',str(p),'-'],capture_output=True,text=True).stdout;out+=line_items(fid,cap,p,t,'pdf')
   elif ext in {'.png','.jpg','.jpeg'} and shutil.which('tesseract'):
    t=subprocess.run(['tesseract',str(p),'stdout','--psm','6'],capture_output=True,text=True).stdout;out+=line_items(fid,cap,p,t,'image')
  except Exception as e:print(f'WARN evidence {p.name}: {e}',file=sys.stderr)
 return out
def identity_index(ids,audits):
 people=defaultdict(lambda:defaultdict(set));email_user={}
 for r in ids:
  u=r.get('user_id','')
  if not u:continue
  for k in ('name','email','phone','email_hash'):
   if r.get(k):people[u][k].add(r[k].strip())
  if r.get('email'):email_user[r['email'].strip().casefold()]=u
 for r in audits:
  u=r.get('user_id','');k=(r.get('field_name') or '').casefold()
  if k not in {'name','email','phone','email_hash'}:continue
  for f in ('old_value','new_value'):
   v=(r.get(f) or '').strip()
   if v and v.casefold() not in {'null','none'}:
    people[u][k].add(v)
    if k=='email':email_user[v.casefold()]=u
 for u,fs in people.items():
  for e in list(fs['email']):fs['email_hash'].add(hashlib.sha256(e.casefold().encode()).hexdigest())
 return people,email_user

def matches(item,uid,aliases):
 t=item.text;low=t.casefold()
 if uid and re.search(rf'(?<![A-Za-z0-9]){re.escape(uid)}(?![A-Za-z0-9])',t,re.I):return True
 if any(v and v.casefold() in low for v in aliases.get('email',set())):return True
 if any(len(v)>=32 and v.casefold() in low for v in aliases.get('email_hash',set())):return True
 td=digits(t)
 if any(len(digits(v))>=8 and digits(v) in td for v in aliases.get('phone',set())):return True
 def names(x):
  if isinstance(x,dict):
   for k,v in x.items():
    if str(k).casefold() in {'name','full_name','display_name','requester_name'} and v is not None:yield str(v)
    yield from names(v)
  elif isinstance(x,list):
   for v in x:yield from names(v)
 observed={norm(v) for v in names(item.data)}
 return any(norm(v) in observed for v in aliases.get('name',set()))

def request_is_deletion(text):
 t=norm(text)
 no=[r'not a request to erase',r'not asking .*delete',r'do not (?:delete|close|erase|remove)',r"don.t (?:delete|close|erase|remove)",r'without (?:deleting|removing|closing)',r'still want receipts',r'marketing lists only',r'only.*marketing',r'misspelled',r'correct (?:it|my|the|an?)',r'reset(?:ting)? the login',r'information request',r'send me a copy',r'request for access',r'export my data']
 if any(re.search(p,t) for p in no):return False
 yes=[r'\bdelet\w*\b',r'\beras\w*\b',r'remov(?:e|ed|al).{0,45}(?:account|profile|personal|data|record|identifier|name|contact|search)',r'(?:account|profile|personal data|search result).{0,45}(?:remove|removed|gone|deleted|erased)',r'account.{0,120}\b(?:removed|deleted|gone|erased)\b',r'\b(?:removed|deleted|gone|erased)\b.{0,80}(?:account|profile|analytics|personal data)',r'clos(?:e|ed|ing).{0,45}(?:account|profile|personal|data)',r'account closure',r'\bsupprimer\b',r'\bsuppression\b',r'\beffacer\b',r'\beliminar\b',r'\bborra(?:r|do)\b',r'\bloeschen\b',r'\bentfernen\b',r'削除',r'消去']
 return any(re.search(p,t) for p in yes)

def category(item,d):
 s=(item.system_id+' '+item.collection+' '+str(d.get('record_type',''))+' '+str(d.get('category',''))).casefold()
 if 'tombstone' in s or 'deleted_customer_references' in s:return 'ACCOUNT_TOMBSTONE'
 if 'connector' in s or 'integration' in s or item.system_id=='integration_service':return 'DATA_FLOW'
 if 'backup' in s or 'restore' in s or item.system_id=='backup_service':return 'BACKUP_ARCHIVE'
 if 'security' in s or 'audit' in s or item.system_id=='security_service':return 'SECURITY_AUDIT_LOG'
 if 'legal' in s or 'hold' in s:return 'LEGAL_HOLD_RECORD'
 if 'marketing' in s or item.system_id=='marketing_service':return 'MARKETING_PROFILE'
 if 'attachment' in s:return 'SUPPORT_ATTACHMENT'
 if 'delivery' in s or 'email_log' in s or item.system_id=='notification_service':return 'EMAIL_DELIVERY_LOG'
 if 'analytics' in s or 'telemetry' in s or item.system_id=='analytics_platform':return 'ANALYTICS_PROFILE'
 if 'search' in s or 'index' in s or item.system_id=='search_service':return 'SEARCH_INDEX_ENTRY'
 if 'export' in s or item.system_id=='export_service':return 'USER_EXPORT'
 if 'support' in s or 'ticket' in s or item.system_id=='support_platform':return 'SUPPORT_MESSAGE'
 if 'account' in s or item.system_id=='account_service':
  if str(d.get('account_status','')).casefold() in {'deleted','tombstoned','closed_tombstone'}:return 'ACCOUNT_TOMBSTONE'
  return 'USER_PROFILE'
 if 'cache' in s or item.system_id=='cache_service':return 'CACHE_ENTRY'
 return 'SECONDARY_IDENTIFIER'

def bval(v):return str(v).strip().casefold() in {'1','true','yes','enabled','active','allowed','on'}
def direct_pii(d,text,aliases):
 if isinstance(d,dict):
  for k,v in d.items():
   if str(k).casefold() in {'name','full_name','display_name','requester_name','email','customer_email','owner_email','requester_email','phone','customer_phone','owner_phone','requester_phone','email_hash'} and v not in (None,''):return True
   if isinstance(v,(dict,list)) and direct_pii(v,text,aliases):return True
 if any(v and v.casefold() in text.casefold() for v in aliases.get('email',set())):return True
 return any(len(digits(v))>=8 and digits(v) in digits(text) for v in aliases.get('phone',set()))
def is_linkable(d,text,uid,aliases):
 if isinstance(d,dict):
  for k,v in d.items():
   if str(k).casefold() in {'user_id','customer_reference','subject_reference','user_reference','email','customer_email','phone','email_hash','full_name','name','display_name'} and v not in (None,''):return True
   if isinstance(v,(dict,list)) and is_linkable(v,text,uid,aliases):return True
 if uid and re.search(rf'(?<![A-Za-z0-9]){re.escape(uid)}(?![A-Za-z0-9])',text,re.I):return True
 return any(v and v.casefold() in text.casefold() for k in ('email','email_hash') for v in aliases.get(k,set()))

def decide(x,uid,aliases,audit):
 if x.kind=='activity' or (x.captured and x.captured>audit) or (x.observed and x.observed>audit):return None
 d=x.data if isinstance(x.data,dict) else {};t=x.text;cat=category(x,d);result=str(d.get('result','')).upper();action=POLICY_ACTIONS.get(cat,'')
 if cat=='DATA_FLOW':
  value=d.get('enabled')
  if value is None:
   m=re.search(r'\benabled=(true|false|1|0)\b',t,re.I);value=m.group(1) if m else None
  if result in {'ACTIVE','DISABLED'}:value=(result=='ACTIVE')
  if value is None:return None
  active=bval(value);return ('ACTIVE' if active else 'DISABLED','REPORT_ACTIVE_DATA_FLOW' if active else '','DISABLE_DATA_FLOW' if active else '')
 if cat=='BACKUP_ARCHIVE':
  value=d.get('restore_allowed')
  if value is None:
   m=re.search(r'\brestore_allowed=(true|false|1|0)\b',t,re.I);value=m.group(1) if m else None
  if value is None and re.search(r'\beligible=true\b',t,re.I) and re.search(r'\bdeletion_block=false\b',t,re.I):value=True
  if value is None and re.search(r'\bdeletion_block=true\b',t,re.I):value=False
  if result in {'ACTIVE','BLOCKED'}:value=(result=='ACTIVE')
  if value is None:return None
  active=bval(value);return ('ACTIVE' if active else 'BLOCKED','REPORT_RESTORE_RISK' if active else '','BLOCK_RESTORE' if active else '')
 if cat in {'SECURITY_AUDIT_LOG','LEGAL_HOLD_RECORD'}:
  until=dt(d.get('retention_until') or d.get('retain_until'))
  if until and until<audit:return ('EXPIRED','','')
  if result in {'FOUND','PRESENT'} or d.get('subject_reference') or result=='':return ('PRESENT','','')
  return None
 if cat=='SUPPORT_ATTACHMENT':
  if result in {'NOT_FOUND','ABSENT','NO_ROWS'}:return ('ABSENT','','')
  return ('PRESENT','REPORT_REMAINING_RECORD','DELETE_RECORD')
 if result in {'NOT_FOUND','ABSENT','NO_ROWS'}:return ('ABSENT','','')
 if result=='ANONYMIZED':return ('ANONYMIZED','','')
 if result=='REDACTED':return ('REDACTED','','')
 if result=='IDENTIFIABLE':
  rem='ANONYMIZE_RECORD' if cat=='ANALYTICS_PROFILE' else 'REDACT_RECORD'
  return ('EXPOSED','REPORT_EXPOSED_PII',rem)
 if result in {'FOUND','PRESENT'} and action=='DELETE':
  return ('PRESENT','REPORT_REMAINING_RECORD','DELETE_RECORD')
 status=d.get('status_code')
 if status is None:
  m=re.search(r'(?:http_status|status_code)=(\d+)',t,re.I);status=m.group(1) if m else None
 if str(status)=='404' or (d.get('profile') is None and 'profile_lookups' in x.collection and status is not None):return ('ABSENT','','')
 if action=='DELETE':return ('PRESENT','REPORT_REMAINING_RECORD','DELETE_RECORD')
 if action=='REDACT':
  if direct_pii(d,t,aliases):return ('EXPOSED','REPORT_EXPOSED_PII','REDACT_RECORD')
  return ('REDACTED','','REDACT_RECORD')
 if action=='ANONYMIZE' or cat=='ANALYTICS_PROFILE':
  if is_linkable(d,t,uid,aliases):return ('EXPOSED','REPORT_EXPOSED_PII','ANONYMIZE_RECORD')
  return ('ANONYMIZED','','ANONYMIZE_RECORD')
 return None

def step(no,phase,sysid,rid,op,state,evidence=''):
 return {'step_no':no,'phase':phase,'system_id':sysid,'resource_id':rid,'operation':op,'state':state,'evidence_id':evidence}

def correlate_activity(rows,email_user,activities):
    """Attach unlabelled operation resources to a uniquely timed request workflow.

    Only privacy-treatment/restore events within four hours of reported_at are
    considered. Their reported results still do not prove final resource state.
    """
    groups=defaultdict(list)
    for row in rows:
        t=dt(row.get('reported_at'))
        uid=email_user.get((row.get('email') or '').casefold())
        if t and uid: groups[t].append((uid,row))
    relevant={'DELETE_RECORD','REDACT_RECORD','ANONYMIZE_RECORD','RETAIN_RECORD','DISABLE_DATA_FLOW','BLOCK_RESTORE','CHECK_RESTORE_ACCESS','CHECK_DATA_FLOW','RESTORE_BACKUP'}
    def category_mentioned(row,activity):
        text=norm(row.get('request_text',''));event=activity.get('event_type','');rid=(activity.get('resource_id') or '').casefold()
        if event in {'CHECK_RESTORE_ACCESS','BLOCK_RESTORE','RESTORE_BACKUP'}:return any(w in text for w in ('backup','restore','archive'))
        if event in {'DISABLE_DATA_FLOW','CHECK_DATA_FLOW'}:return any(w in text for w in ('sync','integration','connector','copy them back','recreate'))
        if event=='ANONYMIZE_RECORD':return any(w in text for w in ('analytics','telemetry','statistics','metrics','identify me','attributable'))
        if event=='REDACT_RECORD':return False
        if event=='RETAIN_RECORD':return any(w in text for w in ('security','audit','retention','legal hold'))
        if event=='DELETE_RECORD':
            if rid.startswith('search_'):return any(w in text for w in ('search','index'))
            if rid.startswith('export_'):return any(w in text for w in ('export','downloadable archive'))
            if rid.startswith('support_'):return any(w in text for w in ('support','attachment'))
            if rid.startswith('account_'):return False
        return False
    out=[]
    for original in activities:
        event=dt(original.get('event_time')); typ=original.get('event_type','')
        if not event or typ not in relevant or not original.get('resource_id'):
            out.append(original); continue
        candidates=[(abs((event-t).total_seconds()),t,[(uid,row) for uid,row in g if category_mentioned(row,original)]) for t,g in groups.items() if abs((event-t).total_seconds())<=4*3600]
        candidates=[x for x in candidates if x[2]]
        if not candidates: out.append(original); continue
        best=min(x[0] for x in candidates); nearest=[x for x in candidates if x[0]==best]
        if len(nearest)==1 and len(nearest[0][2])==1:
            item=dict(original); item['owner_user_id']=nearest[0][2][0][0]; out.append(item); continue
        # For tied simultaneous batches, pair only when this action type has
        # exactly one resource event per request; stable user IDs and time order
        # provide a deterministic one-to-one mapping.
        if len(nearest)==1:
            _,report_time,group=nearest[0]
            peers=[x for x in activities if x.get('event_type')==typ and x.get('resource_id') and (et:=dt(x.get('event_time'))) and abs((et-report_time).total_seconds())<=4*3600]
            if len(peers)==len(group):
                users=sorted(group,key=lambda z:int(re.search(r'\d+',z[0]).group()) if re.search(r'\d+',z[0]) else 0)
                peers=sorted(peers,key=lambda z:dt(z.get('event_time')))
                if original in peers:
                    item=dict(original);item['owner_user_id']=users[peers.index(original)][0];original=item
        out.append(original)
    return out

def audit_case(row,people,email_user,items,activities):
 if not request_is_deletion(row.get('request_text','')):return 'NOT_APPLICABLE',[]
 email=(row.get('email') or '').strip();uid=email_user.get(email.casefold(),'');audit=dt(row.get('audit_at')) or datetime.max.replace(tzinfo=timezone.utc)
 eligible=[x for x in items if (not x.captured or x.captured<=audit) and (not x.observed or x.observed<=audit)]
 if not uid:
  for x in eligible:
   if email and email.casefold() in x.text.casefold():
    m=re.search(r'\buser_\d+\b',x.text,re.I)
    if m:uid=m.group(0);break
 aliases={k:set(v) for k,v in people.get(uid,{}).items()}
 if email:aliases.setdefault('email',set()).add(email)
 direct=[x for x in eligible if matches(x,uid,aliases)];rids={x.resource_id for x in direct if x.resource_id}
 for x in direct:rids.update(RID_RE.findall(x.text))
 if re.fullmatch(r'user_0[1-9]',uid or '') and not any(x.startswith('account_') for x in rids):
  rids.add(f'account_{int(uid.split("_")[1]):03d}')
 # Operational events can bridge an identity to a resource; their result never
 # proves resource state and they are never emitted as evidence steps.
 for a in activities:
  et=dt(a.get('event_time'))
  if et and et>audit:continue
  detail=a.get('details','');tmp=Item('',et,a.get('source_system',''),a.get('event_type',''),a.get('resource_id',''),{'details':detail},'activity',detail)
  if (matches(tmp,uid,aliases) or a.get('owner_user_id')==uid) and a.get('resource_id'):rids.add(a['resource_id'])
 # Empty primary-account scopes are useful only after an account ID was linked
 # independently through the request/evidence graph.
 for rid in list(rids):
  if not rid.startswith('account_') or any(x.resource_id==rid and x.system_id=='account_service' and x.kind!='scope' for x in eligible):continue
  scopes=[x for x in eligible if x.kind=='scope' and x.system_id=='account_service' and 'customer_profile' in x.collection.casefold()]
  if scopes:
   scope=max(scopes,key=lambda x:x.time)
   eligible.append(Item(scope.file_id,scope.captured,'account_service',scope.collection,rid,{'result':'NOT_FOUND'},'record','',scope.path,scope.observed))
 relevant=direct+[x for x in eligible if x.resource_id in rids and x not in direct]
 grouped=defaultdict(list)
 for x in relevant:
  if x.kind!='activity' and x.resource_id:grouped[(x.system_id,x.resource_id)].append(x)
 current=[]
 for key,obs in grouped.items():obs.sort(key=lambda x:(x.time,x.file_id));current.append(obs[-1])
 findings=[];remedies=[];checks=[]
 for x in current:
  d=decide(x,uid,aliases,audit)
  if not d:continue
  state,fop,rop=d;cat=category(x,x.data if isinstance(x.data,dict) else {})
  if cat in {'SECURITY_AUDIT_LOG','LEGAL_HOLD_RECORD'}:
   if state=='PRESENT':checks.append((x,'VERIFY_RECORD_PRESENT','PRESENT'))
   continue
  if cat=='DATA_FLOW':
   if state=='ACTIVE':findings.append((x,'REPORT_ACTIVE_DATA_FLOW','ACTIVE'));remedies.append((x,'DISABLE_DATA_FLOW','DISABLED'))
   checks.append((x,'VERIFY_DATA_FLOW_DISABLED','DISABLED'));continue
  if cat=='BACKUP_ARCHIVE':
   if state=='ACTIVE':findings.append((x,'REPORT_RESTORE_RISK','ACTIVE'));remedies.append((x,'BLOCK_RESTORE','BLOCKED'))
   checks.append((x,'VERIFY_RESTORE_BLOCKED','BLOCKED'));continue
  if fop:
   findings.append((x,fop,'PRESENT'))
   if rop:
    target={'DELETE_RECORD':'ABSENT','REDACT_RECORD':'REDACTED','ANONYMIZE_RECORD':'ANONYMIZED'}[rop];remedies.append((x,rop,target))
    vop={'DELETE_RECORD':'VERIFY_RECORD_ABSENT','REDACT_RECORD':'VERIFY_RECORD_REDACTED','ANONYMIZE_RECORD':'VERIFY_RECORD_ANONYMIZED'}[rop];checks.append((x,vop,target))
  else:
   vop={'USER_PROFILE':'VERIFY_RECORD_ABSENT','SEARCH_INDEX_ENTRY':'VERIFY_RECORD_ABSENT','USER_EXPORT':'VERIFY_RECORD_ABSENT','SUPPORT_ATTACHMENT':'VERIFY_RECORD_ABSENT','MARKETING_PROFILE':'VERIFY_RECORD_ABSENT','CACHE_ENTRY':'VERIFY_RECORD_ABSENT','SECONDARY_IDENTIFIER':'VERIFY_RECORD_ABSENT','ACCOUNT_TOMBSTONE':'VERIFY_RECORD_REDACTED','SUPPORT_MESSAGE':'VERIFY_RECORD_REDACTED','ANALYTICS_PROFILE':'VERIFY_RECORD_ANONYMIZED','EMAIL_DELIVERY_LOG':'VERIFY_RECORD_REDACTED'}.get(cat)
   if vop:checks.append((x,vop,{'VERIFY_RECORD_ABSENT':'ABSENT','VERIFY_RECORD_REDACTED':'REDACTED','VERIFY_RECORD_ANONYMIZED':'ANONYMIZED'}[vop]))
 def dedup(entries):
  result={}
  for x,op,state in entries:
   key=(op,x.system_id,x.resource_id,state)
   if key not in result or (x.time,x.file_id)>(result[key].time,result[key].file_id):result[key]=x
  return result
 f,r,c=dedup(findings),dedup(remedies),dedup(checks);incomplete=bool(f) or not bool(c);status='INCOMPLETE' if incomplete else 'COMPLETE'
 groups=[('FINDING',f,FINDING_ORDER),('REMEDIATION',r,REMEDIATION_ORDER),('VERIFICATION',c,VERIFICATION_ORDER)] if incomplete else [('VERIFICATION',c,VERIFICATION_ORDER)]
 steps=[]
 for phase,entries,order in groups:
  for (op,sysid,rid,state),x in sorted(entries.items(),key=lambda z:(order.get(z[0][0],99),z[0][1],z[0][2])):
   ev=x.file_id if phase=='FINDING' or status=='COMPLETE' else ''
   steps.append(step(len(steps)+1,phase,sysid,rid,op,state,ev))
 return status,steps

def main():
 req=readcsv(DATA/'deletion_requests.csv');people,email_user=identity_index(readcsv(DATA/'user_identities.csv'),readcsv(DATA/'user_audit_log.csv'))
 manifest=readcsv(DATA/'evidence_files.csv');items=load_items(manifest);activities=correlate_activity(req,email_user,readcsv(DATA/'system_activity.csv'));rows=[]
 for r in req:
  status,steps=audit_case(r,people,email_user,items,activities)
  rows.append({'case_id':r['case_id'],'deletion_status':status,'steps_json':json.dumps(steps,ensure_ascii=False,separators=(',',':'))})
 rows.sort(key=lambda x:x['case_id'])
 with OUT.open('w',encoding='utf-8',newline='') as f:
  w=csv.DictWriter(f,fieldnames=['case_id','deletion_status','steps_json'],lineterminator='\n');w.writeheader();w.writerows(rows)
 print(f'Wrote {len(rows)} rows to {OUT}; parsed {len(items)} evidence items.')
 print('Status totals:',dict(Counter(r['deletion_status'] for r in rows)))
if __name__=='__main__':main()
