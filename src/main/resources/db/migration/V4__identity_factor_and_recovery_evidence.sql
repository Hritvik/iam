alter table verified_identifier add constraint verified_identifier_id_identity_unique
    unique (identifier_id,identity_id);

create table authentication_factor (
    factor_id text primary key check (factor_id ~ '^fac_[A-Za-z0-9_-]{22,128}$'),
    identity_id text not null references human_identity(identity_id) on delete restrict,
    verified_identifier_id text not null,
    factor_type text not null check (factor_type = 'EMAIL_OTP'),
    state text not null check (state = 'ACTIVE'),
    version bigint not null default 1 check (version = 1),
    created_at timestamptz not null default transaction_timestamp(),
    updated_at timestamptz not null default transaction_timestamp(),
    unique (identity_id,factor_type),
    unique (verified_identifier_id,factor_type),
    foreign key (verified_identifier_id,identity_id)
      references verified_identifier(identifier_id,identity_id) on delete restrict
);

create table recovery_method (
    recovery_method_id text primary key check (recovery_method_id ~ '^rcv_[A-Za-z0-9_-]{22,128}$'),
    identity_id text not null references human_identity(identity_id) on delete restrict,
    verified_identifier_id text not null,
    recovery_type text not null check (recovery_type = 'VERIFIED_EMAIL'),
    state text not null check (state = 'ACTIVE'),
    version bigint not null default 1 check (version = 1),
    created_at timestamptz not null default transaction_timestamp(),
    updated_at timestamptz not null default transaction_timestamp(),
    unique (identity_id,recovery_type),
    unique (verified_identifier_id,recovery_type),
    foreign key (verified_identifier_id,identity_id)
      references verified_identifier(identifier_id,identity_id) on delete restrict
);

alter table audit_fact drop constraint audit_fact_fact_type_check;
alter table audit_fact drop constraint audit_fact_subject_kind_check;
alter table audit_fact drop constraint audit_fact_subject_shape_check;
alter table audit_fact drop constraint audit_fact_semantics_check;
alter table audit_fact add constraint audit_fact_fact_type_check check (fact_type in
 ('OUTBOX_EVENT_RECORDED','OUTBOX_DELIVERY_QUARANTINED','IDENTITY_CREATED','IDENTIFIER_CHALLENGE_ISSUED',
  'IDENTIFIER_CHALLENGE_SUPERSEDED','IDENTIFIER_CHALLENGE_LOCKED','IDENTIFIER_VERIFIED',
  'AUTHENTICATION_FACTOR_REGISTERED','RECOVERY_METHOD_REGISTERED'));
alter table audit_fact add constraint audit_fact_subject_kind_check check
 (subject_kind in ('SYSTEM','APP_REGISTRATION','EVENT','IDENTITY','VERIFICATION_CHALLENGE','VERIFIED_IDENTIFIER',
  'AUTHENTICATION_FACTOR','RECOVERY_METHOD'));
alter table audit_fact add constraint audit_fact_subject_shape_check check (
 (subject_kind='SYSTEM' and subject_id is null) or
 (subject_kind='APP_REGISTRATION' and subject_id ~ '^[a-z][a-z0-9-]{2,63}$') or
 (subject_kind='EVENT' and subject_id ~ '^evt_[A-Za-z0-9_-]{16,128}$') or
 (subject_kind='IDENTITY' and subject_id ~ '^hid_[A-Za-z0-9_-]{22,128}$') or
 (subject_kind='VERIFICATION_CHALLENGE' and subject_id ~ '^vch_[A-Za-z0-9_-]{22,128}$') or
 (subject_kind='VERIFIED_IDENTIFIER' and subject_id ~ '^vid_[A-Za-z0-9_-]{22,128}$') or
 (subject_kind='AUTHENTICATION_FACTOR' and subject_id ~ '^fac_[A-Za-z0-9_-]{22,128}$') or
 (subject_kind='RECOVERY_METHOD' and subject_id ~ '^rcv_[A-Za-z0-9_-]{22,128}$'));
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
  and event_id is null and reason_code is null and outcome='SUCCEEDED'));

create trigger authentication_factor_immutable before update or delete on authentication_factor
    for each row execute function reject_immutable_fact_mutation();
create trigger recovery_method_immutable before update or delete on recovery_method
    for each row execute function reject_immutable_fact_mutation();

create function ensure_email_otp_factor(p_identity_id text,p_expected_version bigint,p_factor_id text,
 p_audit_id text,p_correlation_id text)
returns table(outcome text,evidence_id text,identity_version bigint,security_version bigint)
language plpgsql security definer set search_path=pg_catalog,public as $$
declare current_identity public.human_identity%rowtype;
declare email_id text;
declare existing_id text;
begin
 select * into current_identity from public.human_identity where identity_id=p_identity_id for update;
 if not found or current_identity.state <> 'ACTIVE' then return query select 'REJECTED',null::text,null::bigint,null::bigint; return; end if;
 select factor_id into existing_id from public.authentication_factor
  where identity_id=p_identity_id and factor_type='EMAIL_OTP';
 if existing_id is not null then
  return query select 'EXISTING',existing_id,current_identity.version,current_identity.security_version; return;
 end if;
 if current_identity.version <> p_expected_version then
  return query select 'CONFLICT',null::text,current_identity.version,current_identity.security_version; return;
 end if;
 select identifier_id into email_id from public.verified_identifier
  where identity_id=p_identity_id and identifier_type='EMAIL' order by identifier_id limit 1;
 if email_id is null then return query select 'REJECTED',null::text,current_identity.version,current_identity.security_version; return; end if;
 insert into public.authentication_factor(factor_id,identity_id,verified_identifier_id,factor_type,state)
 values(p_factor_id,p_identity_id,email_id,'EMAIL_OTP','ACTIVE');
 update public.human_identity i set version=i.version+1,security_version=i.security_version+1,
  updated_at=transaction_timestamp() where identity_id=p_identity_id;
 insert into public.audit_fact(audit_id,fact_type,subject_kind,subject_id,outcome,correlation_id,occurred_at)
 values(p_audit_id,'AUTHENTICATION_FACTOR_REGISTERED','AUTHENTICATION_FACTOR',p_factor_id,'SUCCEEDED',
  p_correlation_id,transaction_timestamp());
 return query select 'CREATED',p_factor_id,current_identity.version+1,current_identity.security_version+1;
exception when unique_violation then
 select factor_id into existing_id from public.authentication_factor
  where identity_id=p_identity_id and factor_type='EMAIL_OTP';
 if existing_id is not null then
  select version,security_version into current_identity.version,current_identity.security_version
   from public.human_identity where identity_id=p_identity_id;
  return query select 'EXISTING',existing_id,current_identity.version,current_identity.security_version; return;
 end if;
 raise;
end $$;

create function ensure_verified_email_recovery(p_identity_id text,p_expected_version bigint,p_recovery_id text,
 p_audit_id text,p_correlation_id text)
returns table(outcome text,evidence_id text,identity_version bigint,security_version bigint)
language plpgsql security definer set search_path=pg_catalog,public as $$
declare current_identity public.human_identity%rowtype;
declare email_id text;
declare existing_id text;
begin
 select * into current_identity from public.human_identity where identity_id=p_identity_id for update;
 if not found or current_identity.state <> 'ACTIVE' then return query select 'REJECTED',null::text,null::bigint,null::bigint; return; end if;
 select recovery_method_id into existing_id from public.recovery_method
  where identity_id=p_identity_id and recovery_type='VERIFIED_EMAIL';
 if existing_id is not null then
  return query select 'EXISTING',existing_id,current_identity.version,current_identity.security_version; return;
 end if;
 if current_identity.version <> p_expected_version then
  return query select 'CONFLICT',null::text,current_identity.version,current_identity.security_version; return;
 end if;
 select identifier_id into email_id from public.verified_identifier
  where identity_id=p_identity_id and identifier_type='EMAIL' order by identifier_id limit 1;
 if email_id is null then return query select 'REJECTED',null::text,current_identity.version,current_identity.security_version; return; end if;
 insert into public.recovery_method(recovery_method_id,identity_id,verified_identifier_id,recovery_type,state)
 values(p_recovery_id,p_identity_id,email_id,'VERIFIED_EMAIL','ACTIVE');
 update public.human_identity i set version=i.version+1,security_version=i.security_version+1,
  updated_at=transaction_timestamp() where identity_id=p_identity_id;
 insert into public.audit_fact(audit_id,fact_type,subject_kind,subject_id,outcome,correlation_id,occurred_at)
 values(p_audit_id,'RECOVERY_METHOD_REGISTERED','RECOVERY_METHOD',p_recovery_id,'SUCCEEDED',
  p_correlation_id,transaction_timestamp());
 return query select 'CREATED',p_recovery_id,current_identity.version+1,current_identity.security_version+1;
exception when unique_violation then
 select recovery_method_id into existing_id from public.recovery_method
  where identity_id=p_identity_id and recovery_type='VERIFIED_EMAIL';
 if existing_id is not null then
  select version,security_version into current_identity.version,current_identity.security_version
   from public.human_identity where identity_id=p_identity_id;
  return query select 'EXISTING',existing_id,current_identity.version,current_identity.security_version; return;
 end if;
 raise;
end $$;

alter table authentication_factor owner to iam_migrator;
alter table recovery_method owner to iam_migrator;
alter function ensure_email_otp_factor(text,bigint,text,text,text) owner to iam_migrator;
alter function ensure_verified_email_recovery(text,bigint,text,text,text) owner to iam_migrator;
revoke all on authentication_factor,recovery_method from public;
revoke all on function ensure_email_otp_factor(text,bigint,text,text,text),
 ensure_verified_email_recovery(text,bigint,text,text,text) from public;
grant select on authentication_factor,recovery_method to iam_runtime;
grant execute on function ensure_email_otp_factor(text,bigint,text,text,text),
 ensure_verified_email_recovery(text,bigint,text,text,text) to iam_runtime;
grant all on authentication_factor,recovery_method to iam_migrator;
