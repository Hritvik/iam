do $$ begin
 if not exists(select 1 from pg_roles where rolname='iam_migrator')
    or not exists(select 1 from pg_roles where rolname='iam_runtime')
    or not exists(select 1 from pg_roles where rolname='iam_relay')
    or not exists(select 1 from pg_roles where rolname='iam_registration_reconciler') then
  raise exception 'required IAM privilege roles are not provisioned';
 end if;
end $$;

create table dpop_nonce(
 nonce_id text primary key constraint dpop_nonce_id_format check(nonce_id ~ '^dpn_[A-Za-z0-9_-]{22,128}$'),
 digest bytea not null constraint dpop_nonce_digest_length check(octet_length(digest)=32),
 digest_key_version smallint not null constraint dpop_nonce_key_version check(digest_key_version between 1 and 32767),
 purpose text not null constraint dpop_nonce_purpose check(purpose in ('TOKEN','RESOURCE')),
 app_registration_id text not null references app_registration(app_registration_id) on delete restrict,
 client_id text not null references client_registration(client_id) on delete restrict,
 proof_key_thumbprint_digest bytea not null constraint dpop_nonce_thumbprint_length
   check(octet_length(proof_key_thumbprint_digest)=32),
 method text not null constraint dpop_nonce_method check(method ~ '^[A-Z]{3,16}$'),
 target_digest bytea not null constraint dpop_nonce_target_length check(octet_length(target_digest)=32),
 status text not null constraint dpop_nonce_status check(status in ('ISSUED','CONSUMED','EXPIRED','SUPERSEDED')),
 expires_at timestamptz not null,
 consumed_at timestamptz,
 version bigint not null default 1 constraint dpop_nonce_version check(version between 1 and 9223372036854775807),
 created_at timestamptz not null default transaction_timestamp(),
 correlation_id text not null constraint dpop_nonce_correlation check(correlation_id ~ '^cor_[A-Za-z0-9_-]{16,128}$'),
 constraint dpop_nonce_time_order check(expires_at>created_at),
 constraint dpop_nonce_terminal_coherence check(
  (status='ISSUED' and consumed_at is null) or (status='CONSUMED' and consumed_at is not null)
  or (status in ('EXPIRED','SUPERSEDED') and consumed_at is null)),
 unique(digest,digest_key_version)
);
create unique index one_live_dpop_nonce_binding on dpop_nonce(
 purpose,app_registration_id,client_id,proof_key_thumbprint_digest,method,target_digest) where status='ISSUED';

create table dpop_replay(
 replay_digest bytea primary key constraint dpop_replay_digest_length check(octet_length(replay_digest)=32),
 digest_key_version smallint not null constraint dpop_replay_key_version check(digest_key_version between 1 and 32767),
 purpose text not null constraint dpop_replay_purpose check(purpose in ('TOKEN','RESOURCE')),
 expires_at timestamptz not null,
 created_at timestamptz not null default transaction_timestamp(),
 constraint dpop_replay_time_order check(expires_at>created_at)
);

create table token_issuance_audit_fact(
 audit_id text primary key constraint token_issuance_audit_id check(audit_id ~ '^aud_[A-Za-z0-9_-]{16,128}$'),
 authorization_code_id text not null unique references authorization_code(authorization_code_id) on delete restrict,
 app_registration_id text not null references app_registration(app_registration_id) on delete restrict,
 client_id text not null references client_registration(client_id) on delete restrict,
 outcome text not null constraint token_issuance_outcome check(outcome='SUCCEEDED'),
 correlation_id text not null constraint token_issuance_correlation check(correlation_id ~ '^cor_[A-Za-z0-9_-]{16,128}$'),
 occurred_at timestamptz not null default transaction_timestamp()
);

create function reject_dpop_nonce_binding_mutation() returns trigger language plpgsql as $$ begin
 if old.nonce_id<>new.nonce_id or old.digest<>new.digest or old.digest_key_version<>new.digest_key_version
   or old.purpose<>new.purpose or old.app_registration_id<>new.app_registration_id
   or old.client_id<>new.client_id or old.proof_key_thumbprint_digest<>new.proof_key_thumbprint_digest
   or old.method<>new.method or old.target_digest<>new.target_digest or old.expires_at<>new.expires_at
   or old.created_at<>new.created_at or old.correlation_id<>new.correlation_id then
  raise exception using message='dpop_nonce_binding_immutable',errcode='55000';
 end if;
 if not (old.status='ISSUED' and new.status in ('CONSUMED','EXPIRED','SUPERSEDED') and new.version=old.version+1) then
  raise exception using message='dpop_nonce_transition_rejected',errcode='55000';
 end if;
 return new;
end $$;
create trigger dpop_nonce_guard before update on dpop_nonce for each row execute function reject_dpop_nonce_binding_mutation();
create trigger dpop_replay_immutable before update on dpop_replay
 for each row execute function reject_immutable_fact_mutation();
create trigger token_issuance_audit_immutable before update or delete on token_issuance_audit_fact
 for each row execute function reject_immutable_fact_mutation();

create function issue_dpop_nonce(p_nonce_id text,p_digest bytea,p_digest_key_version smallint,p_purpose text,
 p_app_registration_id text,p_client_id text,p_thumbprint_digest bytea,p_method text,p_target_digest bytea,
 p_replay_digests bytea[],p_replay_key_versions smallint[],p_replay_retention_seconds integer,
 p_lifetime_seconds integer,p_correlation_id text,
 p_thumbprint_aliases bytea[] default null,p_target_aliases bytea[] default null)
returns table(result text,nonce_id text,expires_at timestamptz,version bigint)
language plpgsql volatile security definer set search_path=pg_catalog,public as $$
declare claimed integer;
begin
 if p_nonce_id is null or p_digest is null or p_digest_key_version is null or p_purpose is null
  or p_app_registration_id is null or p_client_id is null or p_thumbprint_digest is null or p_method is null
  or p_target_digest is null or p_replay_digests is null or p_replay_key_versions is null
  or p_replay_retention_seconds is null or p_lifetime_seconds is null or p_correlation_id is null
  or cardinality(p_replay_digests) not between 1 and 8
  or cardinality(p_replay_digests)<>cardinality(p_replay_key_versions)
  or array_position(p_replay_digests,null) is not null or array_position(p_replay_key_versions,null) is not null
  or p_replay_retention_seconds not between 120 and 600 or p_lifetime_seconds not between 30 and 300
  or cardinality(coalesce(p_thumbprint_aliases,'{}'::bytea[])) not between 0 and 8
  or cardinality(coalesce(p_target_aliases,'{}'::bytea[])) not between 0 and 8
  or array_position(p_thumbprint_aliases,null) is not null
  or array_position(p_target_aliases,null) is not null
  or exists(select 1 from unnest(coalesce(p_thumbprint_aliases,'{}'::bytea[])) alias(value)
            where octet_length(alias.value)<>32)
  or exists(select 1 from unnest(coalesce(p_target_aliases,'{}'::bytea[])) alias(value)
            where octet_length(alias.value)<>32) then
  return query select 'REJECTED'::text,null::text,null::timestamptz,null::bigint; return;
 end if;
 perform pg_advisory_xact_lock(hashtextextended(
  p_purpose||'|'||p_app_registration_id||'|'||p_client_id||'|'||p_method,0));
 perform 1 from public.canonical_registration() r
  where r->>'appRegistrationId'=p_app_registration_id and r->'client'->>'clientId'=p_client_id;
 if not found then return query select 'REJECTED'::text,null::text,null::timestamptz,null::bigint; return; end if;
 begin
  insert into public.dpop_replay(replay_digest,digest_key_version,purpose,expires_at)
  select candidate.digest,candidate.key_version,p_purpose,
   transaction_timestamp()+make_interval(secs=>p_replay_retention_seconds)
  from unnest(p_replay_digests,p_replay_key_versions) candidate(digest,key_version)
  on conflict do nothing;
  get diagnostics claimed=row_count;
  if claimed<>cardinality(p_replay_digests) then raise unique_violation; end if;
 exception when unique_violation then
  return query select 'REJECTED'::text,null::text,null::timestamptz,null::bigint; return;
 end;
 update public.dpop_nonce n set status='SUPERSEDED',version=n.version+1
  where n.purpose=p_purpose and n.app_registration_id=p_app_registration_id and n.client_id=p_client_id
   and n.method=p_method and n.status='ISSUED'
   and (n.proof_key_thumbprint_digest=p_thumbprint_digest
        or n.proof_key_thumbprint_digest=any(coalesce(p_thumbprint_aliases,'{}'::bytea[])))
   and (n.target_digest=p_target_digest
        or n.target_digest=any(coalesce(p_target_aliases,'{}'::bytea[])));
 insert into public.dpop_nonce(nonce_id,digest,digest_key_version,purpose,app_registration_id,client_id,
  proof_key_thumbprint_digest,method,target_digest,status,expires_at,correlation_id)
 values(p_nonce_id,p_digest,p_digest_key_version,p_purpose,p_app_registration_id,p_client_id,
  p_thumbprint_digest,p_method,p_target_digest,'ISSUED',transaction_timestamp()+make_interval(secs=>p_lifetime_seconds),
  p_correlation_id);
 return query select 'ISSUED'::text,n.nonce_id,n.expires_at,n.version from public.dpop_nonce n where n.nonce_id=p_nonce_id;
exception when integrity_constraint_violation or data_exception then
 raise exception using message='dpop_nonce_issue_rejected',errcode='22023';
end $$;

create function consume_dpop_nonce_and_claim_replay(p_nonce_digests bytea[],p_digest_key_versions smallint[],
 p_purpose text,p_app_registration_id text,p_client_id text,p_thumbprint_digests bytea[],p_method text,
 p_target_digests bytea[],p_replay_digests bytea[],p_replay_key_versions smallint[],p_replay_retention_seconds integer,
 p_correlation_id text) returns text
language plpgsql volatile security definer set search_path=pg_catalog,public as $$
declare claimed integer; claimed_purpose text;
begin
 if p_nonce_digests is null or p_digest_key_versions is null or p_purpose is null
  or p_app_registration_id is null or p_client_id is null or p_thumbprint_digests is null or p_method is null
  or p_target_digests is null or p_replay_digests is null
  or p_replay_key_versions is null or p_replay_retention_seconds is null or p_correlation_id is null
  or cardinality(p_nonce_digests) not between 1 and 8
  or cardinality(p_nonce_digests)<>cardinality(p_digest_key_versions)
  or cardinality(p_thumbprint_digests)<>cardinality(p_digest_key_versions)
  or cardinality(p_target_digests)<>cardinality(p_digest_key_versions)
  or cardinality(p_replay_digests) not between 1 and 8
  or cardinality(p_replay_digests)<>cardinality(p_replay_key_versions)
  or array_position(p_nonce_digests,null) is not null or array_position(p_digest_key_versions,null) is not null
  or array_position(p_thumbprint_digests,null) is not null or array_position(p_target_digests,null) is not null
  or array_position(p_replay_digests,null) is not null or array_position(p_replay_key_versions,null) is not null
  or p_replay_retention_seconds not between 120 and 600 then return 'REJECTED'; end if;
 begin
  update public.dpop_nonce n set status='CONSUMED',consumed_at=transaction_timestamp(),version=n.version+1
   where n.digest=p_nonce_digests[array_position(p_digest_key_versions,n.digest_key_version)]
    and n.digest_key_version=any(p_digest_key_versions) and n.purpose=p_purpose
    and n.app_registration_id=p_app_registration_id and n.client_id=p_client_id
    and n.proof_key_thumbprint_digest=p_thumbprint_digests[array_position(p_digest_key_versions,n.digest_key_version)]
    and n.method=p_method
    and n.target_digest=p_target_digests[array_position(p_digest_key_versions,n.digest_key_version)]
    and n.status='ISSUED' and n.expires_at>transaction_timestamp()
   returning n.purpose into claimed_purpose;
  get diagnostics claimed=row_count;
  if claimed<>1 then raise no_data_found; end if;
  insert into public.dpop_replay(replay_digest,digest_key_version,purpose,expires_at)
  select candidate.digest,candidate.key_version,claimed_purpose,
   transaction_timestamp()+make_interval(secs=>p_replay_retention_seconds)
  from unnest(p_replay_digests,p_replay_key_versions) candidate(digest,key_version)
  on conflict do nothing;
  get diagnostics claimed=row_count;
  if claimed<>cardinality(p_replay_digests) then raise unique_violation; end if;
 exception when no_data_found or unique_violation then return 'REJECTED';
 end;
 return 'CONSUMED';
end $$;

create function claim_dpop_resource_replay(p_replay_digests bytea[],p_key_versions smallint[],p_retention_seconds integer)
returns boolean language plpgsql volatile security definer set search_path=pg_catalog,public as $$
declare claimed integer; begin
 if p_replay_digests is null or p_key_versions is null or p_retention_seconds is null
  or cardinality(p_replay_digests) not between 1 and 8
  or cardinality(p_replay_digests)<>cardinality(p_key_versions)
  or array_position(p_replay_digests,null) is not null or array_position(p_key_versions,null) is not null
  or p_retention_seconds not between 120 and 600 then return false; end if;
 begin
  insert into public.dpop_replay(replay_digest,digest_key_version,purpose,expires_at)
  select candidate.digest,candidate.key_version,'RESOURCE',
   transaction_timestamp()+make_interval(secs=>p_retention_seconds)
  from unnest(p_replay_digests,p_key_versions) candidate(digest,key_version)
  on conflict do nothing;
  get diagnostics claimed=row_count;
  if claimed<>cardinality(p_replay_digests) then raise unique_violation; end if;
 exception when unique_violation then return false;
 end;
 return true;
end $$;

create function append_token_issuance_audit(p_audit_id text,p_code_id text,p_app_id text,p_client_id text,
 p_correlation_id text) returns boolean language plpgsql volatile security definer set search_path=pg_catalog,public as $$
begin
 insert into public.token_issuance_audit_fact(audit_id,authorization_code_id,app_registration_id,client_id,
  outcome,correlation_id) values(p_audit_id,p_code_id,p_app_id,p_client_id,'SUCCEEDED',p_correlation_id);
 return true;
exception when integrity_constraint_violation or data_exception then
 raise exception using message='token_issuance_audit_rejected',errcode='22023';
end $$;

create function read_active_token_security_context(p_human_identity_id text,p_app_registration_id text,
 p_client_id text,p_app_subject text) returns table(result text,security_version bigint)
language plpgsql volatile security definer set search_path=pg_catalog,public as $$
declare current_security_version bigint;
begin
 if p_human_identity_id is null or p_app_registration_id is null or p_client_id is null or p_app_subject is null then
  return query select 'REJECTED'::text,null::bigint; return;
 end if;
 select h.security_version into current_security_version from public.human_identity h
  where h.identity_id=p_human_identity_id and h.state='ACTIVE' for update;
 if not found then return query select 'REJECTED'::text,null::bigint; return; end if;
 perform 1 from public.canonical_registration() r
  where r->>'appRegistrationId'=p_app_registration_id and r->'client'->>'clientId'=p_client_id;
 if not found then return query select 'REJECTED'::text,null::bigint; return; end if;
 perform 1 from public.app_subject s where s.human_identity_id=p_human_identity_id
  and s.app_registration_id=p_app_registration_id and s.app_subject=p_app_subject for share;
 if not found then return query select 'REJECTED'::text,null::bigint; return; end if;
 return query select 'ACTIVE'::text,current_security_version;
end $$;

create function cleanup_expired_dpop_state(p_batch_size integer) returns integer
language plpgsql volatile security definer set search_path=pg_catalog,public as $$
declare removed integer:=0; affected integer; remaining integer; begin
 if p_batch_size is null or p_batch_size not between 1 and 1000 then return 0; end if;
 delete from public.dpop_replay where replay_digest in
  (select replay_digest from public.dpop_replay where expires_at<=transaction_timestamp()
   order by expires_at limit p_batch_size for update skip locked);
 get diagnostics removed=row_count;
 remaining:=p_batch_size-removed;
 if remaining>0 then
  delete from public.dpop_nonce where nonce_id in
   (select nonce_id from public.dpop_nonce where status in ('CONSUMED','EXPIRED','SUPERSEDED')
    and expires_at<=transaction_timestamp() order by expires_at limit remaining for update skip locked);
  get diagnostics affected=row_count;
  removed:=removed+affected;
 end if;
 remaining:=p_batch_size-removed;
 if remaining<=0 then return removed; end if;
 update public.dpop_nonce n set status='EXPIRED',version=n.version+1
  where n.nonce_id in (select nonce_id from public.dpop_nonce where status='ISSUED'
   and expires_at<=transaction_timestamp() order by expires_at limit remaining for update skip locked);
 get diagnostics affected=row_count; return removed+affected;
end $$;

alter table dpop_nonce owner to iam_migrator;
alter table dpop_replay owner to iam_migrator;
alter table token_issuance_audit_fact owner to iam_migrator;
alter function reject_dpop_nonce_binding_mutation() owner to iam_migrator;
alter function issue_dpop_nonce(text,bytea,smallint,text,text,text,bytea,text,bytea,bytea[],smallint[],integer,integer,text,bytea[],bytea[]) owner to iam_migrator;
alter function consume_dpop_nonce_and_claim_replay(bytea[],smallint[],text,text,text,bytea[],text,bytea[],bytea[],smallint[],integer,text) owner to iam_migrator;
alter function claim_dpop_resource_replay(bytea[],smallint[],integer) owner to iam_migrator;
alter function append_token_issuance_audit(text,text,text,text,text) owner to iam_migrator;
alter function read_active_token_security_context(text,text,text,text) owner to iam_migrator;
alter function cleanup_expired_dpop_state(integer) owner to iam_migrator;
revoke all on dpop_nonce,dpop_replay,token_issuance_audit_fact from public;
revoke all on function issue_dpop_nonce(text,bytea,smallint,text,text,text,bytea,text,bytea,bytea[],smallint[],integer,integer,text,bytea[],bytea[]) from public;
revoke all on function consume_dpop_nonce_and_claim_replay(bytea[],smallint[],text,text,text,bytea[],text,bytea[],bytea[],smallint[],integer,text) from public;
revoke all on function claim_dpop_resource_replay(bytea[],smallint[],integer) from public;
revoke all on function append_token_issuance_audit(text,text,text,text,text) from public;
revoke all on function read_active_token_security_context(text,text,text,text) from public;
revoke all on function cleanup_expired_dpop_state(integer) from public;
grant execute on function issue_dpop_nonce(text,bytea,smallint,text,text,text,bytea,text,bytea,bytea[],smallint[],integer,integer,text,bytea[],bytea[]) to iam_runtime;
grant execute on function consume_dpop_nonce_and_claim_replay(bytea[],smallint[],text,text,text,bytea[],text,bytea[],bytea[],smallint[],integer,text) to iam_runtime;
grant execute on function claim_dpop_resource_replay(bytea[],smallint[],integer) to iam_runtime;
grant execute on function append_token_issuance_audit(text,text,text,text,text) to iam_runtime;
grant execute on function read_active_token_security_context(text,text,text,text) to iam_runtime;
grant execute on function cleanup_expired_dpop_state(integer) to iam_runtime;
grant all on dpop_nonce,dpop_replay,token_issuance_audit_fact to iam_migrator;
