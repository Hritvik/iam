do $$ begin
 if not exists(select 1 from pg_roles where rolname='iam_migrator')
    or not exists(select 1 from pg_roles where rolname='iam_runtime') then
  raise exception 'required IAM privilege roles are not provisioned';
 end if;
end $$;

alter table client_registration add constraint client_registration_app_client_unique unique(app_registration_id,client_id);
alter table resource_registration add constraint resource_registration_app_resource_unique unique(app_registration_id,resource_id);

create table authorization_server_issuer(
 singleton boolean primary key default true constraint authorization_server_issuer_singleton check(singleton),
 issuer text not null unique constraint authorization_server_issuer_format
   check(issuer='https://iam.distracted.invalid')
);
insert into authorization_server_issuer(singleton,issuer) values(true,'https://iam.distracted.invalid');

create table authorization_request(
 authorization_request_id text primary key constraint authorization_request_id_format
   check(authorization_request_id ~ '^arq_[A-Za-z0-9_-]{22,128}$'),
 issuer text not null constraint authorization_request_issuer_length check(length(issuer) between 8 and 256),
 app_registration_id text not null references app_registration(app_registration_id) on delete restrict,
 client_id text not null references client_registration(client_id) on delete restrict,
 resource_id text not null references resource_registration(resource_id) on delete restrict,
 resource_audience text not null constraint authorization_request_audience_length check(length(resource_audience) between 8 and 256),
 human_identity_id text not null references human_identity(identity_id) on delete restrict,
 redirect_uri text not null constraint authorization_request_redirect_length check(length(redirect_uri) between 8 and 512),
 scope text not null constraint authorization_request_scope_format check(length(scope) between 1 and 512 and scope !~ '(^ |  | $)'),
 state_digest bytea not null constraint authorization_request_state_digest_length check(octet_length(state_digest)=32),
 nonce_digest bytea not null constraint authorization_request_nonce_digest_length check(octet_length(nonce_digest)=32),
 code_challenge bytea not null constraint authorization_request_challenge_length check(octet_length(code_challenge)=32),
 code_challenge_method text not null constraint authorization_request_challenge_method check(code_challenge_method='S256'),
 status text not null constraint authorization_request_status check(status in ('AUTHORIZED','EXPIRED')),
 authorized_at timestamptz not null,
 expires_at timestamptz not null,
 correlation_id text not null constraint authorization_request_correlation_format check(correlation_id ~ '^cor_[A-Za-z0-9_-]{16,128}$'),
 version bigint not null constraint authorization_request_version check(version>=1),
 constraint authorization_request_expiry check(expires_at>authorized_at),
 constraint authorization_request_registration_binding foreign key(app_registration_id,client_id)
   references client_registration(app_registration_id,client_id) on delete restrict,
 constraint authorization_request_resource_binding foreign key(app_registration_id,resource_id)
   references resource_registration(app_registration_id,resource_id) on delete restrict
);

create table authorization_code(
 authorization_code_id text primary key constraint authorization_code_id_format
   check(authorization_code_id ~ '^acd_[A-Za-z0-9_-]{22,128}$'),
 authorization_request_id text not null unique references authorization_request(authorization_request_id) on delete restrict,
 code_digest bytea not null constraint authorization_code_digest_length check(octet_length(code_digest)=32),
 digest_key_version smallint not null constraint authorization_code_key_version check(digest_key_version>=1),
 status text not null constraint authorization_code_status check(status in ('ISSUED','CONSUMED','EXPIRED')),
 issued_at timestamptz not null,
 expires_at timestamptz not null,
 consumed_at timestamptz,
 consumed_correlation_id text constraint authorization_code_consumed_correlation_format
   check(consumed_correlation_id is null or consumed_correlation_id ~ '^cor_[A-Za-z0-9_-]{16,128}$'),
 version bigint not null constraint authorization_code_version check(version>=1),
 constraint authorization_code_digest_unique unique(digest_key_version,code_digest),
 constraint authorization_code_expiry check(expires_at>issued_at),
 constraint authorization_code_consumption check((status='CONSUMED')=(consumed_at is not null)
   and (status='CONSUMED')=(consumed_correlation_id is not null))
);

create table authorization_audit_fact(
 audit_id text primary key constraint authorization_audit_id_format check(audit_id ~ '^aud_[A-Za-z0-9_-]{16,128}$'),
 fact_type text not null constraint authorization_audit_fact_type
   check(fact_type in ('AUTHORIZATION_CODE_ISSUED','AUTHORIZATION_CODE_CONSUMED')),
 authorization_request_id text not null references authorization_request(authorization_request_id) on delete restrict,
 authorization_code_id text not null references authorization_code(authorization_code_id) on delete restrict,
 app_registration_id text not null references app_registration(app_registration_id) on delete restrict,
 client_id text not null references client_registration(client_id) on delete restrict,
 outcome text not null constraint authorization_audit_outcome check(outcome='SUCCEEDED'),
 correlation_id text not null constraint authorization_audit_correlation_format
   check(correlation_id ~ '^cor_[A-Za-z0-9_-]{16,128}$'),
 causation_id text constraint authorization_audit_causation_format
   check(causation_id is null or causation_id ~ '^cau_[A-Za-z0-9_-]{16,128}$'),
 occurred_at timestamptz not null,
 constraint authorization_audit_once unique(fact_type,authorization_code_id)
);
create trigger authorization_audit_fact_immutable before update or delete on authorization_audit_fact
 for each row execute function reject_immutable_fact_mutation();

create function issue_authorization_code(
 p_request_id text,p_code_id text,p_issuer text,p_app text,p_client text,p_resource text,p_audience text,
 p_identity text,p_redirect text,p_scope text,p_state_digest bytea,p_nonce_digest bytea,p_challenge bytea,
 p_code_digest bytea,p_key_version smallint,p_lifetime_seconds integer,p_correlation text)
returns table(issued_at timestamptz,expires_at timestamptz,version bigint)
language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_now timestamptz := transaction_timestamp(); v_expires timestamptz; v_registration jsonb;
begin
 if p_request_id is null or p_code_id is null or p_issuer is null or p_app is null or p_client is null
    or p_resource is null or p_audience is null or p_identity is null or p_redirect is null or p_scope is null
    or p_state_digest is null or p_nonce_digest is null or p_challenge is null or p_code_digest is null
    or p_key_version is null or p_correlation is null or p_lifetime_seconds is null
    or p_lifetime_seconds not between 60 and 300
    or not exists(select 1 from public.authorization_server_issuer i where i.issuer=p_issuer) then
   raise exception 'authorization_issue_rejected';
 end if;
 v_expires := v_now + make_interval(secs=>p_lifetime_seconds);
 select public.canonical_registration() into v_registration;
 if not exists(select 1 from public.human_identity where identity_id=p_identity and state='ACTIVE')
    or v_registration is null or v_registration->>'appRegistrationId'<>p_app
    or v_registration->'client'->>'clientId'<>p_client
    or v_registration->'resource'->>'resourceId'<>p_resource
    or v_registration->'resource'->>'audience'<>p_audience
    or not (v_registration->'client'->'redirectUris' @> to_jsonb(array[p_redirect]))
    or not (v_registration->'resource'->'allowedScopes' @> to_jsonb(string_to_array(p_scope,' '))) then
   raise exception 'authorization_issue_rejected';
 end if;
 insert into public.authorization_request values(p_request_id,p_issuer,p_app,p_client,p_resource,p_audience,
   p_identity,p_redirect,p_scope,p_state_digest,p_nonce_digest,p_challenge,'S256','AUTHORIZED',v_now,v_expires,p_correlation,1);
 insert into public.authorization_code values(p_code_id,p_request_id,p_code_digest,p_key_version,'ISSUED',
   v_now,v_expires,null,null,1);
 insert into public.authorization_audit_fact values('aud_'||substring(p_code_id from 5),
   'AUTHORIZATION_CODE_ISSUED',p_request_id,p_code_id,p_app,p_client,'SUCCEEDED',p_correlation,null,v_now);
 return query select v_now,v_expires,1::bigint;
exception when integrity_constraint_violation or data_exception then
 raise exception 'authorization_issue_rejected';
end $$;

create function digest_equal(p_left bytea,p_right bytea) returns boolean
language plpgsql immutable strict security definer set search_path=pg_catalog,public as $$
declare v_difference integer := 0; v_index integer;
begin
 if octet_length(p_left)<>octet_length(p_right) then return false; end if;
 for v_index in 0..octet_length(p_left)-1 loop
   v_difference := v_difference | (get_byte(p_left,v_index) # get_byte(p_right,v_index));
 end loop;
 return v_difference=0;
end $$;

create function authorization_code_protection(p_code_id text)
returns table(digest_key_version smallint,code_digest bytea,version bigint)
language sql stable security definer set search_path=pg_catalog,public as $$
 select c.digest_key_version,c.code_digest,c.version from public.authorization_code c
 where c.authorization_code_id=p_code_id
$$;

create function consume_authorization_code(
 p_code_id text,p_code_digest bytea,p_key_version smallint,p_issuer text,p_client text,p_redirect text,
 p_calculated_challenge bytea,p_expected_version bigint,p_correlation text)
returns table(result text,authorization_request_id text,app_registration_id text,client_id text,
 resource_id text,resource_audience text,human_identity_id text,scope text,state_digest bytea,nonce_digest bytea,
 consumed_at timestamptz,version bigint)
language plpgsql security definer set search_path=pg_catalog,public as $$
declare v_now timestamptz := transaction_timestamp(); v_code public.authorization_code%rowtype;
 v_request public.authorization_request%rowtype; v_registration jsonb;
begin
 if p_code_id is null or p_code_digest is null or p_key_version is null or p_issuer is null or p_client is null
    or p_redirect is null or p_calculated_challenge is null or p_expected_version is null or p_correlation is null then
  return query select 'REJECTED',null::text,null::text,null::text,null::text,null::text,
   null::text,null::text,null::bytea,null::bytea,null::timestamptz,null::bigint; return;
 end if;
 select * into v_code from public.authorization_code where authorization_code_id=p_code_id for update;
 if not found then return query select 'REJECTED',null::text,null::text,null::text,null::text,null::text,
   null::text,null::text,null::bytea,null::bytea,null::timestamptz,null::bigint; return; end if;
 select r.* into v_request from public.authorization_request r
   where r.authorization_request_id=v_code.authorization_request_id for update;
 select public.canonical_registration() into v_registration;
 if v_registration is null or not exists(select 1 from public.authorization_server_issuer i where i.issuer=p_issuer)
    or v_registration->>'appRegistrationId'<>v_request.app_registration_id
    or v_registration->'client'->>'clientId'<>v_request.client_id
    or v_registration->'resource'->>'resourceId'<>v_request.resource_id
    or v_registration->'resource'->>'audience'<>v_request.resource_audience
    or not (v_registration->'client'->'redirectUris' @> to_jsonb(array[v_request.redirect_uri]))
    or not (v_registration->'resource'->'allowedScopes' @> to_jsonb(string_to_array(v_request.scope,' '))) then
  return query select 'REJECTED',null::text,null::text,null::text,null::text,null::text,
   null::text,null::text,null::bytea,null::bytea,null::timestamptz,null::bigint; return;
 end if;
 if v_code.status='ISSUED' and (v_code.expires_at<=v_now or v_request.expires_at<=v_now) then
   update public.authorization_code set status='EXPIRED',version=authorization_code.version+1
    where authorization_code_id=p_code_id and status='ISSUED';
   update public.authorization_request r set status='EXPIRED',version=r.version+1
    where r.authorization_request_id=v_request.authorization_request_id and r.status='AUTHORIZED';
   return query select 'REJECTED',null::text,null::text,null::text,null::text,null::text,
    null::text,null::text,null::bytea,null::bytea,null::timestamptz,null::bigint; return;
 end if;
 if v_code.status<>'ISSUED' or v_code.version<>p_expected_version or v_code.digest_key_version<>p_key_version
    or not public.digest_equal(v_code.code_digest,p_code_digest) or v_request.status<>'AUTHORIZED'
    or v_request.issuer<>p_issuer or v_request.client_id<>p_client or v_request.redirect_uri<>p_redirect
    or not public.digest_equal(v_request.code_challenge,p_calculated_challenge) then
   return query select 'REJECTED',null::text,null::text,null::text,null::text,null::text,
    null::text,null::text,null::bytea,null::bytea,null::timestamptz,null::bigint; return;
 end if;
 update public.authorization_code set status='CONSUMED',consumed_at=v_now,consumed_correlation_id=p_correlation,
   version=authorization_code.version+1 where authorization_code_id=p_code_id and status='ISSUED';
 insert into public.authorization_audit_fact values('aud_c_'||substring(p_code_id from 5),
   'AUTHORIZATION_CODE_CONSUMED',v_request.authorization_request_id,p_code_id,v_request.app_registration_id,
   v_request.client_id,'SUCCEEDED',p_correlation,null,v_now);
 return query select 'CONSUMED',v_request.authorization_request_id,v_request.app_registration_id,
   v_request.client_id,v_request.resource_id,v_request.resource_audience,v_request.human_identity_id,v_request.scope,
   v_request.state_digest,v_request.nonce_digest,v_now,v_code.version+1;
end $$;

alter table authorization_request owner to iam_migrator;
alter table authorization_code owner to iam_migrator;
alter table authorization_audit_fact owner to iam_migrator;
alter table authorization_server_issuer owner to iam_migrator;
alter function issue_authorization_code(text,text,text,text,text,text,text,text,text,text,bytea,bytea,bytea,bytea,smallint,integer,text) owner to iam_migrator;
alter function digest_equal(bytea,bytea) owner to iam_migrator;
alter function authorization_code_protection(text) owner to iam_migrator;
alter function consume_authorization_code(text,bytea,smallint,text,text,text,bytea,bigint,text) owner to iam_migrator;
revoke all on authorization_request,authorization_code,authorization_audit_fact,authorization_server_issuer from public;
revoke all on function issue_authorization_code(text,text,text,text,text,text,text,text,text,text,bytea,bytea,bytea,bytea,smallint,integer,text) from public;
revoke all on function digest_equal(bytea,bytea) from public;
revoke all on function authorization_code_protection(text) from public;
revoke all on function consume_authorization_code(text,bytea,smallint,text,text,text,bytea,bigint,text) from public;
grant execute on function issue_authorization_code(text,text,text,text,text,text,text,text,text,text,bytea,bytea,bytea,bytea,smallint,integer,text) to iam_runtime;
grant execute on function authorization_code_protection(text) to iam_runtime;
grant execute on function consume_authorization_code(text,bytea,smallint,text,text,text,bytea,bigint,text) to iam_runtime;
grant all on authorization_request,authorization_code,authorization_audit_fact,authorization_server_issuer to iam_migrator;
