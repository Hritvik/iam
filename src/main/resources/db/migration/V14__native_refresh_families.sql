do $$ begin
 if not exists(select 1 from pg_roles where rolname='iam_migrator')
    or not exists(select 1 from pg_roles where rolname='iam_runtime') then
  raise exception 'required IAM privilege roles are not provisioned';
 end if;
end $$;

create table refresh_family(
 family_id text primary key constraint refresh_family_id_format
   check(family_id ~ '^rfm_[A-Za-z0-9_-]{22,128}$'),
 human_identity_id text not null references human_identity(identity_id) on delete restrict,
 app_registration_id text not null references app_registration(app_registration_id) on delete restrict,
 client_id text not null references client_registration(client_id) on delete restrict,
 resource_id text not null references resource_registration(resource_id) on delete restrict,
 resource_audience text not null constraint refresh_family_audience_length
   check(length(resource_audience) between 8 and 256),
 scope text not null constraint refresh_family_scope_format
   check(length(scope) between 1 and 512 and scope !~ '(^ |  | $)'),
 dpop_jkt text not null constraint refresh_family_dpop_format
   check(dpop_jkt ~ '^[A-Za-z0-9_-]{43}$'),
 security_version bigint not null constraint refresh_family_security_version check(security_version>=1),
 status text not null constraint refresh_family_status check(status in ('ACTIVE','REVOKED','EXPIRED')),
 created_at timestamptz not null,
 last_used_at timestamptz not null,
 idle_expires_at timestamptz not null,
 absolute_expires_at timestamptz not null,
 revoked_at timestamptz,
 revocation_reason text constraint refresh_family_revocation_reason
   check(revocation_reason in ('REUSE','WRONG_KEY','SECURITY_VERSION','REGISTRATION_CHANGED',
     'IDENTITY_DISABLED','IDENTITY_DELETED','OPERATOR')),
 version bigint not null constraint refresh_family_version check(version>=1),
 constraint refresh_family_expiry check(absolute_expires_at>created_at and idle_expires_at>created_at
   and idle_expires_at<=absolute_expires_at),
 constraint refresh_family_revocation check((status='REVOKED')=(revoked_at is not null)
   and (status='REVOKED')=(revocation_reason is not null)),
 constraint refresh_family_registration_binding foreign key(app_registration_id,client_id)
   references client_registration(app_registration_id,client_id) on delete restrict,
 constraint refresh_family_resource_binding foreign key(app_registration_id,resource_id)
   references resource_registration(app_registration_id,resource_id) on delete restrict
);
create index refresh_family_identity_status on refresh_family(human_identity_id,status);

create table refresh_token(
 refresh_token_id text primary key constraint refresh_token_id_format
   check(refresh_token_id ~ '^rft_[A-Za-z0-9_-]{22,128}$'),
 family_id text not null references refresh_family(family_id) on delete restrict,
 generation integer not null constraint refresh_token_generation check(generation between 1 and 1000),
 token_digest bytea not null constraint refresh_token_digest_length check(octet_length(token_digest)=32),
 status text not null constraint refresh_token_status check(status in ('ACTIVE','USED','REVOKED','EXPIRED')),
 issued_at timestamptz not null,
 expires_at timestamptz not null,
 used_at timestamptz,
 replaced_by text references refresh_token(refresh_token_id) on delete restrict,
 version bigint not null constraint refresh_token_version check(version>=1),
 constraint refresh_token_generation_unique unique(family_id,generation),
 constraint refresh_token_digest_unique unique(token_digest),
 constraint refresh_token_expiry check(expires_at>issued_at),
 constraint refresh_token_use check((status='USED')=(used_at is not null)
   and (status='USED')=(replaced_by is not null))
);
create index refresh_token_family_status on refresh_token(family_id,status);

create table refresh_audit_fact(
 audit_id text primary key constraint refresh_audit_id_format
   check(audit_id ~ '^aud_[A-Za-z0-9_-]{16,128}$'),
 fact_type text not null constraint refresh_audit_fact_type
   check(fact_type in ('REFRESH_ISSUED','REFRESH_ROTATED','REFRESH_REUSE_DETECTED','REFRESH_FAMILY_REVOKED')),
 family_id text not null references refresh_family(family_id) on delete restrict,
 refresh_token_id text references refresh_token(refresh_token_id) on delete restrict,
 app_registration_id text not null references app_registration(app_registration_id) on delete restrict,
 client_id text not null references client_registration(client_id) on delete restrict,
 outcome text not null constraint refresh_audit_outcome check(outcome='RECORDED'),
 reason text constraint refresh_audit_reason
   check(reason in ('REUSE','WRONG_KEY','SECURITY_VERSION','REGISTRATION_CHANGED',
     'IDENTITY_DISABLED','IDENTITY_DELETED','OPERATOR')),
 correlation_id text not null constraint refresh_audit_correlation_format
   check(correlation_id ~ '^cor_[A-Za-z0-9_-]{16,128}$'),
 occurred_at timestamptz not null
);
create trigger refresh_audit_fact_immutable before update or delete on refresh_audit_fact
 for each row execute function reject_immutable_fact_mutation();

create function issue_refresh_family(
 p_family_id text,p_token_id text,p_identity text,p_app text,p_client text,p_resource text,p_audience text,
 p_scope text,p_dpop_jkt text,p_security_version bigint,p_token_digest bytea,p_absolute_seconds integer,
 p_idle_seconds integer,p_correlation text)
returns table(issued_at timestamptz,expires_at timestamptz,absolute_expires_at timestamptz,version bigint)
language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_now timestamptz := transaction_timestamp(); v_absolute timestamptz; v_expires timestamptz;
 v_registration jsonb; v_state text; v_identity_security bigint;
begin
 if p_family_id is null or p_token_id is null or p_identity is null or p_app is null or p_client is null
    or p_resource is null or p_audience is null or p_scope is null or p_dpop_jkt is null
    or p_security_version is null or p_token_digest is null or p_correlation is null
    or p_absolute_seconds is null or p_idle_seconds is null
    or p_absolute_seconds not between 86400 and 7776000
    or p_idle_seconds not between 3600 and 2592000
    or octet_length(p_token_digest)<>32
    or p_dpop_jkt !~ '^[A-Za-z0-9_-]{43}$' then
   raise exception 'refresh_issue_rejected';
 end if;
 select state,security_version into v_state,v_identity_security
   from public.human_identity where identity_id=p_identity;
 if v_state is distinct from 'ACTIVE' or v_identity_security is distinct from p_security_version then
   raise exception 'refresh_issue_rejected';
 end if;
 select public.canonical_registration() into v_registration;
 if v_registration is null or v_registration->>'appRegistrationId'<>p_app
    or v_registration->'client'->>'clientId'<>p_client
    or v_registration->'resource'->>'resourceId'<>p_resource
    or v_registration->'resource'->>'audience'<>p_audience
    or not (v_registration->'resource'->'allowedScopes' @> to_jsonb(string_to_array(p_scope,' '))) then
   raise exception 'refresh_issue_rejected';
 end if;
 v_absolute := v_now + make_interval(secs=>p_absolute_seconds);
 v_expires := least(v_now + make_interval(secs=>p_idle_seconds), v_absolute);
 insert into public.refresh_family values(p_family_id,p_identity,p_app,p_client,p_resource,p_audience,
   p_scope,p_dpop_jkt,p_security_version,'ACTIVE',v_now,v_now,v_expires,v_absolute,null,null,1);
 insert into public.refresh_token values(p_token_id,p_family_id,1,p_token_digest,'ACTIVE',
   v_now,v_expires,null,null,1);
 insert into public.refresh_audit_fact values('aud_i_'||substring(p_token_id from 5 for 100),'REFRESH_ISSUED',
   p_family_id,p_token_id,p_app,p_client,'RECORDED',null,p_correlation,v_now);
 return query select v_now,v_expires,v_absolute,1::bigint;
exception when integrity_constraint_violation or data_exception then
 raise exception 'refresh_issue_rejected';
end $$;

create function rotate_refresh_token(
 p_presented_digest bytea,p_new_digest bytea,p_dpop_jkt text,p_security_version bigint,
 p_new_token_id text,p_correlation text,p_idle_seconds integer)
returns table(result text,family_id text,refresh_token_id text,generation integer,issued_at timestamptz,
 expires_at timestamptz,app_registration_id text,client_id text,resource_id text,resource_audience text,
 human_identity_id text,scope text,absolute_expires_at timestamptz)
language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_now timestamptz := transaction_timestamp(); v_token public.refresh_token%rowtype;
 v_family public.refresh_family%rowtype; v_new_expires timestamptz; v_state text; v_identity_security bigint;
 v_registration jsonb; v_reason text;
begin
 if p_presented_digest is null or octet_length(p_presented_digest)<>32
    or p_new_digest is null or octet_length(p_new_digest)<>32
    or p_dpop_jkt is null or p_dpop_jkt !~ '^[A-Za-z0-9_-]{43}$'
    or p_security_version is null or p_new_token_id is null or p_correlation is null
    or p_idle_seconds is null or p_idle_seconds not between 3600 and 2592000 then
   return query select 'INVALID',null::text,null::text,null::integer,null::timestamptz,null::timestamptz,
     null::text,null::text,null::text,null::text,null::text,null::text,null::timestamptz; return;
 end if;
 select * into v_token from public.refresh_token where refresh_token.token_digest=p_presented_digest for update;
 if not found then
   return query select 'INVALID',null::text,null::text,null::integer,null::timestamptz,null::timestamptz,
     null::text,null::text,null::text,null::text,null::text,null::text,null::timestamptz; return;
 end if;
 select * into v_family from public.refresh_family where refresh_family.family_id=v_token.family_id for update;
 if v_family.status<>'ACTIVE' then
   return query select case when v_family.status='EXPIRED' then 'EXPIRED' else 'REVOKED' end,
     v_family.family_id,null::text,null::integer,null::timestamptz,
     null::timestamptz,null::text,null::text,null::text,null::text,null::text,null::text,null::timestamptz; return;
 end if;
 if v_token.status in ('USED','REVOKED') or v_token.replaced_by is not null then
   if v_family.status='ACTIVE' then
     update public.refresh_family set status='REVOKED',revoked_at=v_now,revocation_reason='REUSE',
       version=refresh_family.version+1 where refresh_family.family_id=v_family.family_id;
     update public.refresh_token set status='REVOKED',version=refresh_token.version+1
       where refresh_token.family_id=v_family.family_id and status='ACTIVE';
     insert into public.refresh_audit_fact values('aud_x_'||md5(v_token.refresh_token_id||clock_timestamp()::text),
       'REFRESH_REUSE_DETECTED',v_family.family_id,v_token.refresh_token_id,v_family.app_registration_id,
       v_family.client_id,'RECORDED','REUSE',p_correlation,v_now);
   end if;
   return query select 'REUSE',v_family.family_id,null::text,null::integer,null::timestamptz,null::timestamptz,
     null::text,null::text,null::text,null::text,null::text,null::text,null::timestamptz; return;
 end if;
 if v_now>=v_family.absolute_expires_at or v_now>=v_family.idle_expires_at or v_now>=v_token.expires_at then
   update public.refresh_family set status='EXPIRED',version=refresh_family.version+1
     where refresh_family.family_id=v_family.family_id and status='ACTIVE';
   update public.refresh_token set status='EXPIRED',version=refresh_token.version+1
     where refresh_token.family_id=v_family.family_id and status='ACTIVE';
   return query select 'EXPIRED',v_family.family_id,null::text,null::integer,null::timestamptz,
     null::timestamptz,null::text,null::text,null::text,null::text,null::text,null::text,null::timestamptz; return;
 end if;
 if v_family.dpop_jkt<>p_dpop_jkt then
   v_reason := 'WRONG_KEY';
 elsif v_family.security_version<>p_security_version then
   v_reason := 'SECURITY_VERSION';
 else
   select state,security_version into v_state,v_identity_security
     from public.human_identity where identity_id=v_family.human_identity_id;
   if v_state is distinct from 'ACTIVE' or v_identity_security is distinct from p_security_version then
     v_reason := 'SECURITY_VERSION';
   end if;
 end if;
 if v_reason is null then
   select public.canonical_registration() into v_registration;
   if v_registration is null or v_registration->>'appRegistrationId'<>v_family.app_registration_id
      or v_registration->'client'->>'clientId'<>v_family.client_id
      or v_registration->'resource'->>'resourceId'<>v_family.resource_id
      or v_registration->'resource'->>'audience'<>v_family.resource_audience
      or not (v_registration->'resource'->'allowedScopes' @> to_jsonb(string_to_array(v_family.scope,' '))) then
     v_reason := 'REGISTRATION_CHANGED';
   end if;
 end if;
 if v_reason is not null then
   update public.refresh_family set status='REVOKED',revoked_at=v_now,revocation_reason=v_reason,
     version=refresh_family.version+1 where refresh_family.family_id=v_family.family_id and status='ACTIVE';
   update public.refresh_token set status='REVOKED',version=refresh_token.version+1
     where refresh_token.family_id=v_family.family_id and status='ACTIVE';
   insert into public.refresh_audit_fact values('aud_x_'||md5(v_token.refresh_token_id||clock_timestamp()::text),
     'REFRESH_FAMILY_REVOKED',v_family.family_id,v_token.refresh_token_id,v_family.app_registration_id,
     v_family.client_id,'RECORDED',v_reason,p_correlation,v_now);
   return query select v_reason,v_family.family_id,null::text,null::integer,null::timestamptz,
     null::timestamptz,null::text,null::text,null::text,null::text,null::text,null::text,null::timestamptz; return;
 end if;
 v_new_expires := least(v_now + make_interval(secs=>p_idle_seconds), v_family.absolute_expires_at);
 insert into public.refresh_token values(p_new_token_id,v_family.family_id,v_token.generation+1,
   p_new_digest,'ACTIVE',v_now,v_new_expires,null,null,1);
 update public.refresh_token set status='USED',used_at=v_now,replaced_by=p_new_token_id,
   version=refresh_token.version+1 where refresh_token.refresh_token_id=v_token.refresh_token_id and status='ACTIVE';
 update public.refresh_family set last_used_at=v_now,idle_expires_at=v_new_expires,
   version=refresh_family.version+1 where refresh_family.family_id=v_family.family_id and status='ACTIVE';
 insert into public.refresh_audit_fact values('aud_r_'||substring(p_new_token_id from 5 for 100),
   'REFRESH_ROTATED',v_family.family_id,p_new_token_id,v_family.app_registration_id,
   v_family.client_id,'RECORDED',null,p_correlation,v_now);
 return query select 'ROTATED',v_family.family_id,p_new_token_id,v_token.generation+1,v_now,v_new_expires,
   v_family.app_registration_id,v_family.client_id,v_family.resource_id,v_family.resource_audience,
   v_family.human_identity_id,v_family.scope,v_family.absolute_expires_at;
end $$;

create function refresh_family_for_token(p_digest bytea)
returns table(family_id text,human_identity_id text,app_registration_id text,client_id text,
 resource_id text,resource_audience text,scope text,security_version bigint,dpop_jkt text,status text)
language plpgsql stable security definer set search_path=pg_catalog,public as $$
begin
 if p_digest is null or octet_length(p_digest)<>32 then return; end if;
 return query select f.family_id,f.human_identity_id,f.app_registration_id,f.client_id,f.resource_id,
   f.resource_audience,f.scope,f.security_version,f.dpop_jkt,f.status
   from public.refresh_token t join public.refresh_family f on f.family_id=t.family_id
   where t.token_digest=p_digest;
end $$;

create function revoke_refresh_family(p_family_id text,p_reason text,p_correlation text)
returns boolean
language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_now timestamptz := transaction_timestamp(); v_family public.refresh_family%rowtype;
begin
 if p_family_id is null or p_reason is null or p_correlation is null
    or p_reason not in ('REUSE','WRONG_KEY','SECURITY_VERSION','REGISTRATION_CHANGED',
      'IDENTITY_DISABLED','IDENTITY_DELETED','OPERATOR') then
   return false;
 end if;
 select * into v_family from public.refresh_family where family_id=p_family_id for update;
 if not found or v_family.status<>'ACTIVE' then return false; end if;
 update public.refresh_family set status='REVOKED',revoked_at=v_now,revocation_reason=p_reason,
   version=refresh_family.version+1 where family_id=p_family_id;
 update public.refresh_token set status='REVOKED',version=refresh_token.version+1
   where family_id=p_family_id and status='ACTIVE';
 insert into public.refresh_audit_fact values('aud_v_'||md5(p_family_id||clock_timestamp()::text),
   'REFRESH_FAMILY_REVOKED',p_family_id,null,v_family.app_registration_id,v_family.client_id,
   'RECORDED',p_reason,p_correlation,v_now);
 return true;
end $$;

alter table refresh_family owner to iam_migrator;
alter table refresh_token owner to iam_migrator;
alter table refresh_audit_fact owner to iam_migrator;
alter function issue_refresh_family(text,text,text,text,text,text,text,text,text,bigint,bytea,integer,integer,text) owner to iam_migrator;
alter function rotate_refresh_token(bytea,bytea,text,bigint,text,text,integer) owner to iam_migrator;
alter function revoke_refresh_family(text,text,text) owner to iam_migrator;
alter function refresh_family_for_token(bytea) owner to iam_migrator;
revoke all on refresh_family,refresh_token,refresh_audit_fact from public;
revoke all on function issue_refresh_family(text,text,text,text,text,text,text,text,text,bigint,bytea,integer,integer,text) from public;
revoke all on function rotate_refresh_token(bytea,bytea,text,bigint,text,text,integer) from public;
revoke all on function revoke_refresh_family(text,text,text) from public;
revoke all on function refresh_family_for_token(bytea) from public;
grant execute on function issue_refresh_family(text,text,text,text,text,text,text,text,text,bigint,bytea,integer,integer,text) to iam_runtime;
grant execute on function rotate_refresh_token(bytea,bytea,text,bigint,text,text,integer) to iam_runtime;
grant execute on function revoke_refresh_family(text,text,text) to iam_runtime;
grant execute on function refresh_family_for_token(bytea) to iam_runtime;
grant all on refresh_family,refresh_token,refresh_audit_fact to iam_migrator;
