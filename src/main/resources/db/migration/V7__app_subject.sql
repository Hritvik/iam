do $$ begin
 if not exists(select 1 from pg_roles where rolname='iam_migrator')
    or not exists(select 1 from pg_roles where rolname='iam_runtime')
    or not exists(select 1 from pg_roles where rolname='iam_relay')
    or not exists(select 1 from pg_roles where rolname='iam_registration_reconciler') then
  raise exception 'required IAM privilege roles are not provisioned';
 end if;
end $$;

create table app_subject(
 app_registration_id text not null references app_registration(app_registration_id) on delete restrict,
 human_identity_id text not null references human_identity(identity_id) on delete restrict,
 app_subject text not null constraint app_subject_format check(app_subject ~ '^aps_[A-Za-z0-9_-]{24}$'),
 version bigint not null default 1 constraint app_subject_version check(version=1),
 created_at timestamptz not null default transaction_timestamp(),
 primary key(app_registration_id,human_identity_id),
 unique(app_registration_id,app_subject),
 unique(app_subject)
);

create trigger app_subject_immutable before update or delete on app_subject
 for each row execute function reject_immutable_fact_mutation();

alter table audit_fact drop constraint audit_fact_fact_type_check;
alter table audit_fact drop constraint audit_fact_subject_kind_check;
alter table audit_fact drop constraint audit_fact_subject_shape_check;
alter table audit_fact drop constraint audit_fact_semantics_check;
alter table audit_fact add constraint audit_fact_fact_type_check check (fact_type in
 ('OUTBOX_EVENT_RECORDED','OUTBOX_DELIVERY_QUARANTINED','IDENTITY_CREATED','IDENTIFIER_CHALLENGE_ISSUED',
  'IDENTIFIER_CHALLENGE_SUPERSEDED','IDENTIFIER_CHALLENGE_LOCKED','IDENTIFIER_VERIFIED',
  'AUTHENTICATION_FACTOR_REGISTERED','RECOVERY_METHOD_REGISTERED','APP_SUBJECT_ALLOCATED'));
alter table audit_fact add constraint audit_fact_subject_kind_check check
 (subject_kind in ('SYSTEM','APP_REGISTRATION','EVENT','IDENTITY','VERIFICATION_CHALLENGE','VERIFIED_IDENTIFIER',
  'AUTHENTICATION_FACTOR','RECOVERY_METHOD','APP_SUBJECT'));
alter table audit_fact add constraint audit_fact_subject_shape_check check (
 (subject_kind='SYSTEM' and subject_id is null) or
 (subject_kind='APP_REGISTRATION' and subject_id ~ '^[a-z][a-z0-9-]{2,63}$') or
 (subject_kind='EVENT' and subject_id ~ '^evt_[A-Za-z0-9_-]{16,128}$') or
 (subject_kind='IDENTITY' and subject_id ~ '^hid_[A-Za-z0-9_-]{22,128}$') or
 (subject_kind='VERIFICATION_CHALLENGE' and subject_id ~ '^vch_[A-Za-z0-9_-]{22,128}$') or
 (subject_kind='VERIFIED_IDENTIFIER' and subject_id ~ '^vid_[A-Za-z0-9_-]{22,128}$') or
 (subject_kind='AUTHENTICATION_FACTOR' and subject_id ~ '^fac_[A-Za-z0-9_-]{22,128}$') or
 (subject_kind='RECOVERY_METHOD' and subject_id ~ '^rcv_[A-Za-z0-9_-]{22,128}$') or
 (subject_kind='APP_SUBJECT' and subject_id ~ '^aps_[A-Za-z0-9_-]{24}$'));
alter table audit_fact add constraint audit_fact_semantics_check check (
 (fact_type='OUTBOX_EVENT_RECORDED' and subject_kind='EVENT' and subject_id=event_id
   and event_id is not null and outcome='SUCCEEDED' and reason_code is null) or
 (fact_type='OUTBOX_DELIVERY_QUARANTINED' and subject_kind='EVENT' and subject_id=event_id
   and event_id is not null and outcome='FAILED' and reason_code is not null) or
 (fact_type in ('IDENTITY_CREATED','IDENTIFIER_CHALLENGE_ISSUED','IDENTIFIER_CHALLENGE_SUPERSEDED',
  'IDENTIFIER_CHALLENGE_LOCKED','IDENTIFIER_VERIFIED') and event_id is null and reason_code is null
  and outcome='SUCCEEDED') or
 (fact_type='AUTHENTICATION_FACTOR_REGISTERED' and subject_kind='AUTHENTICATION_FACTOR'
  and event_id is null and reason_code is null and outcome='SUCCEEDED') or
 (fact_type='RECOVERY_METHOD_REGISTERED' and subject_kind='RECOVERY_METHOD'
  and event_id is null and reason_code is null and outcome='SUCCEEDED') or
 (fact_type='APP_SUBJECT_ALLOCATED' and subject_kind='APP_SUBJECT'
  and event_id is null and reason_code is null and outcome='SUCCEEDED'));
create unique index one_app_subject_allocation_audit on audit_fact(subject_id)
 where fact_type='APP_SUBJECT_ALLOCATED';

create function resolve_app_subject(p_app_registration_id text,p_human_identity_id text,
 p_candidate_app_subject text,p_audit_id text,p_correlation_id text)
returns table(result text,app_subject text,created_at timestamptz,version bigint)
language plpgsql volatile security definer set search_path=pg_catalog,public as $$
declare inserted_count integer; existing_subject text; existing_created_at timestamptz; existing_version bigint;
declare eligible boolean;
begin
 if p_app_registration_id is null or p_human_identity_id is null or p_candidate_app_subject is null
    or p_audit_id is null or p_correlation_id is null
    or p_app_registration_id !~ '^[a-z][a-z0-9-]{2,63}$'
    or p_human_identity_id !~ '^hid_[A-Za-z0-9_-]{22,128}$'
    or p_candidate_app_subject !~ '^aps_[A-Za-z0-9_-]{24}$'
    or p_audit_id !~ '^aud_[A-Za-z0-9_-]{16,128}$'
    or p_correlation_id !~ '^cor_[A-Za-z0-9_-]{16,128}$' then
  return query select 'REJECTED'::text,null::text,null::timestamptz,null::bigint; return;
 end if;
 perform 1 from public.human_identity h where h.identity_id=p_human_identity_id and h.state='ACTIVE' for update;
 if not found then
  return query select 'REJECTED'::text,null::text,null::timestamptz,null::bigint; return;
 end if;
 perform 1 from public.app_registration a
   join public.client_registration c using(app_registration_id)
   join public.resource_registration r using(app_registration_id)
   join public.product_security_policy p using(app_registration_id)
   where a.app_registration_id=p_app_registration_id for share of a,c,r,p;
 if not found then
  return query select 'REJECTED'::text,null::text,null::timestamptz,null::bigint; return;
 end if;
 select exists(select 1 from public.client_redirect_uri x join public.client_registration c using(client_id)
    where c.app_registration_id=p_app_registration_id for share of x)
  and exists(select 1 from public.client_grant_type x join public.client_registration c using(client_id)
    where c.app_registration_id=p_app_registration_id for share of x)
  and exists(select 1 from public.client_pkce_method x join public.client_registration c using(client_id)
    where c.app_registration_id=p_app_registration_id for share of x)
  and exists(select 1 from public.resource_scope x join public.resource_registration r using(resource_id)
    where r.app_registration_id=p_app_registration_id for share of x)
  and exists(select 1 from public.policy_grant_type x where x.app_registration_id=p_app_registration_id for share)
  and exists(select 1 from public.policy_activation_evidence x
    where x.app_registration_id=p_app_registration_id for share)
  into eligible;
 if not eligible then
  return query select 'REJECTED'::text,null::text,null::timestamptz,null::bigint; return;
 end if;
 insert into public.app_subject(app_registration_id,human_identity_id,app_subject)
 values(p_app_registration_id,p_human_identity_id,p_candidate_app_subject)
 on conflict do nothing;
 get diagnostics inserted_count=row_count;
 if inserted_count=1 then
  insert into public.audit_fact(audit_id,fact_type,subject_kind,subject_id,outcome,correlation_id,occurred_at)
  values(p_audit_id,'APP_SUBJECT_ALLOCATED','APP_SUBJECT',p_candidate_app_subject,'SUCCEEDED',
    p_correlation_id,transaction_timestamp());
  return query select 'CREATED'::text,s.app_subject,s.created_at,s.version from public.app_subject s
   where s.app_registration_id=p_app_registration_id and s.human_identity_id=p_human_identity_id;
  return;
 end if;
 select s.app_subject,s.created_at,s.version into existing_subject,existing_created_at,existing_version
  from public.app_subject s where s.app_registration_id=p_app_registration_id
   and s.human_identity_id=p_human_identity_id;
 if found then
  return query select 'EXISTING'::text,existing_subject,existing_created_at,existing_version; return;
 end if;
 return query select 'RETRY_COLLISION'::text,null::text,null::timestamptz,null::bigint;
exception when integrity_constraint_violation or data_exception then
 raise exception using message='app_subject_resolution_rejected',errcode='22023';
end $$;

alter table app_subject owner to iam_migrator;
alter function resolve_app_subject(text,text,text,text,text) owner to iam_migrator;
revoke all on app_subject from public;
revoke all on function resolve_app_subject(text,text,text,text,text) from public;
grant execute on function resolve_app_subject(text,text,text,text,text) to iam_runtime;
grant all on app_subject to iam_migrator;
