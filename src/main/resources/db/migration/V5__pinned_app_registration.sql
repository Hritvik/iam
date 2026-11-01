do $$ begin
 if not exists(select 1 from pg_roles where rolname='iam_migrator')
    or not exists(select 1 from pg_roles where rolname='iam_runtime')
    or not exists(select 1 from pg_roles where rolname='iam_registration_reconciler') then
  raise exception 'required IAM privilege roles are not provisioned';
 end if;
end $$;

create table pinned_registration_allowlist(
 app_registration_id text primary key, manifest_version smallint not null, display_name text not null,
 environment text not null, source_fingerprint char(64) not null, client_id text not null,
 client_type text not null, browser_mode text not null, redirect_uris text[] not null,
 grant_types text[] not null, pkce_methods text[] not null, resource_id text not null,
 audience text not null, scopes text[] not null, require_dpop boolean not null,
 required_pkce_method text not null, activation_evidence text[] not null);
insert into pinned_registration_allowlist values(
 'dutch-development',1,'Dutch Development','development',
 'eb19d5cd14c21e66c334bdd61afd8822da6b2a7d692384a4aa4a96f9f589bafc',
 'dutch-mobile','NATIVE_PUBLIC','EXTERNAL',array['dutch://oauth/callback'],
 array['authorization_code'],array['S256'],'dutch-api','https://api.dutch.invalid',
 array['member:read'],true,'S256',array['verified_identifier','usable_factor','recovery_path']);

create table app_registration(
 app_registration_id text primary key check(app_registration_id ~ '^[a-z][a-z0-9-]{2,63}$'),
 manifest_version smallint not null check(manifest_version=1), display_name text not null check(length(display_name) between 1 and 80),
 environment text not null check(environment in ('development','test','staging','production')),
 source_fingerprint char(64) not null check(source_fingerprint ~ '^[0-9a-f]{64}$'),
 created_at timestamptz not null default transaction_timestamp());
create table client_registration(
 client_id text primary key check(client_id ~ '^[a-z][a-z0-9-]{2,63}$'), app_registration_id text not null unique references app_registration on delete restrict,
 client_type text not null check(client_type='NATIVE_PUBLIC'), browser_mode text not null check(browser_mode='EXTERNAL'),
 created_at timestamptz not null default transaction_timestamp());
create table client_redirect_uri(client_id text not null references client_registration on delete restrict,
 redirect_uri text not null check(length(redirect_uri) between 8 and 512), primary key(client_id,redirect_uri));
create table client_grant_type(client_id text not null references client_registration on delete restrict,
 grant_type text not null check(grant_type='authorization_code'), primary key(client_id,grant_type));
create table client_pkce_method(client_id text not null references client_registration on delete restrict,
 pkce_method text not null check(pkce_method='S256'), primary key(client_id,pkce_method));
create table resource_registration(resource_id text primary key check(resource_id ~ '^[a-z][a-z0-9-]{2,63}$'),
 app_registration_id text not null unique references app_registration on delete restrict,
 audience text not null unique check(length(audience)<=256 and audience ~ '^https://'),
 created_at timestamptz not null default transaction_timestamp());
create table resource_scope(resource_id text not null references resource_registration on delete restrict,
 scope_name text not null check(scope_name ~ '^[a-z][a-z0-9:_-]{0,63}$'), primary key(resource_id,scope_name));
create table product_security_policy(app_registration_id text primary key references app_registration on delete restrict,
 policy_version smallint not null check(policy_version=1), require_dpop boolean not null check(require_dpop),
 required_pkce_method text not null check(required_pkce_method='S256'), created_at timestamptz not null default transaction_timestamp());
create table policy_grant_type(app_registration_id text not null references product_security_policy on delete restrict,
 grant_type text not null check(grant_type='authorization_code'), primary key(app_registration_id,grant_type));
create table policy_activation_evidence(app_registration_id text not null references product_security_policy on delete restrict,
 evidence_type text not null check(evidence_type in ('verified_identifier','usable_factor','recovery_path')),
 primary key(app_registration_id,evidence_type));

create function reconcile_pinned_registration(p_app text,p_version smallint,p_name text,p_environment text,p_fingerprint text,
 p_client text,p_client_type text,p_browser text,p_redirects text[],p_grants text[],p_pkce text[],p_resource text,p_audience text,
 p_scopes text[],p_dpop boolean,p_required_pkce text,p_evidence text[]) returns text
language plpgsql security definer set search_path=pg_catalog,public as $$
declare existing_fingerprint text; same_graph boolean;
begin
 if not exists(select 1 from public.pinned_registration_allowlist a where
    a.app_registration_id=p_app and a.manifest_version=p_version and a.display_name=p_name
    and a.environment=p_environment and a.source_fingerprint=p_fingerprint and a.client_id=p_client
    and a.client_type=p_client_type and a.browser_mode=p_browser and a.redirect_uris=p_redirects
    and a.grant_types=p_grants and a.pkce_methods=p_pkce and a.resource_id=p_resource
    and a.audience=p_audience and a.scopes=p_scopes and a.require_dpop=p_dpop
    and a.required_pkce_method=p_required_pkce and a.activation_evidence=p_evidence) then
  raise exception 'registration_reconcile_not_allowlisted';
 end if;
 if p_app is null or cardinality(p_redirects)<>1 or cardinality(p_grants)<>1 or cardinality(p_pkce)<>1
    or cardinality(p_scopes)<>1 or cardinality(p_evidence)<>3 then raise exception 'registration_reconcile_invalid'; end if;
 perform pg_advisory_xact_lock(hashtextextended(p_app,0));
 select source_fingerprint into existing_fingerprint from public.app_registration where app_registration_id=p_app;
 if found then
  select existing_fingerprint=p_fingerprint and a.manifest_version=p_version and a.display_name=p_name and a.environment=p_environment
   and c.client_id=p_client and c.client_type=p_client_type and c.browser_mode=p_browser
   and r.resource_id=p_resource and r.audience=p_audience and s.require_dpop=p_dpop and s.required_pkce_method=p_required_pkce
   and (select array_agg(redirect_uri order by redirect_uri) from public.client_redirect_uri where client_id=p_client)=
       (select array_agg(x order by x) from unnest(p_redirects)x)
   and (select array_agg(grant_type order by grant_type) from public.client_grant_type where client_id=p_client)=
       (select array_agg(x order by x) from unnest(p_grants)x)
   and (select array_agg(pkce_method order by pkce_method) from public.client_pkce_method where client_id=p_client)=
       (select array_agg(x order by x) from unnest(p_pkce)x)
   and (select array_agg(scope_name order by scope_name) from public.resource_scope where resource_id=p_resource)=
       (select array_agg(x order by x) from unnest(p_scopes)x)
   and (select array_agg(grant_type order by grant_type) from public.policy_grant_type where app_registration_id=p_app)=
       (select array_agg(x order by x) from unnest(p_grants)x)
   and (select array_agg(evidence_type order by evidence_type) from public.policy_activation_evidence where app_registration_id=p_app)=
       (select array_agg(x order by x) from unnest(p_evidence)x)
   into same_graph from public.app_registration a join public.client_registration c using(app_registration_id)
   join public.resource_registration r using(app_registration_id) join public.product_security_policy s using(app_registration_id)
   where a.app_registration_id=p_app;
  return case when coalesce(same_graph,false) then 'UNCHANGED' else 'DRIFT' end;
 end if;
 insert into public.app_registration values(p_app,p_version,p_name,p_environment,p_fingerprint,transaction_timestamp());
 insert into public.client_registration(client_id,app_registration_id,client_type,browser_mode) values(p_client,p_app,p_client_type,p_browser);
 insert into public.client_redirect_uri select p_client,x from unnest(p_redirects)x;
 insert into public.client_grant_type select p_client,x from unnest(p_grants)x;
 insert into public.client_pkce_method select p_client,x from unnest(p_pkce)x;
 insert into public.resource_registration(resource_id,app_registration_id,audience) values(p_resource,p_app,p_audience);
 insert into public.resource_scope select p_resource,x from unnest(p_scopes)x;
 insert into public.product_security_policy(app_registration_id,policy_version,require_dpop,required_pkce_method) values(p_app,1,p_dpop,p_required_pkce);
 insert into public.policy_grant_type select p_app,x from unnest(p_grants)x;
 insert into public.policy_activation_evidence select p_app,x from unnest(p_evidence)x;
 return 'CREATED';
exception when check_violation or foreign_key_violation or unique_violation or not_null_violation then
 raise exception 'registration_reconcile_invalid';
end $$;

create function canonical_registration() returns jsonb
language sql stable security definer set search_path=pg_catalog,public
return (select jsonb_build_object(
 'manifestVersion',a.manifest_version,'appRegistrationId',a.app_registration_id,
 'displayName',a.display_name,'environment',a.environment,
 'client',jsonb_build_object('clientId',c.client_id,'clientType',c.client_type,
   'redirectUris',to_jsonb(l.redirect_uris),'grantTypes',to_jsonb(l.grant_types),
   'pkceMethods',to_jsonb(l.pkce_methods),'browserMode',c.browser_mode),
 'resource',jsonb_build_object('resourceId',r.resource_id,'audience',r.audience,
   'allowedScopes',to_jsonb(l.scopes)),
 'securityPolicy',jsonb_build_object('policyVersion',p.policy_version,'requireDpop',p.require_dpop,
   'requiredPkceMethod',p.required_pkce_method,'allowedGrantTypes',to_jsonb(l.grant_types),
   'requiredActivationEvidence',to_jsonb(l.activation_evidence)))
 from public.pinned_registration_allowlist l
 join public.app_registration a using(app_registration_id)
 join public.client_registration c using(app_registration_id)
 join public.resource_registration r using(app_registration_id)
 join public.product_security_policy p using(app_registration_id)
 where (select count(*) from public.app_registration)=1
   and a.manifest_version=l.manifest_version and a.display_name=l.display_name
   and a.environment=l.environment and a.source_fingerprint=l.source_fingerprint
   and c.client_id=l.client_id and c.client_type=l.client_type and c.browser_mode=l.browser_mode
   and r.resource_id=l.resource_id and r.audience=l.audience
   and p.require_dpop=l.require_dpop and p.required_pkce_method=l.required_pkce_method
   and (select array_agg(redirect_uri order by redirect_uri) from public.client_redirect_uri
        where client_id=c.client_id)=l.redirect_uris
   and (select array_agg(grant_type order by grant_type) from public.client_grant_type
        where client_id=c.client_id)=l.grant_types
   and (select array_agg(pkce_method order by pkce_method) from public.client_pkce_method
        where client_id=c.client_id)=l.pkce_methods
   and (select array_agg(scope_name order by scope_name) from public.resource_scope
        where resource_id=r.resource_id)=l.scopes
   and (select array_agg(grant_type order by grant_type) from public.policy_grant_type
        where app_registration_id=a.app_registration_id)=l.grant_types
   and (select array_agg(evidence_type order by array_position(l.activation_evidence,evidence_type))
        from public.policy_activation_evidence where app_registration_id=a.app_registration_id)=l.activation_evidence);

alter table app_registration owner to iam_migrator;
alter table pinned_registration_allowlist owner to iam_migrator;
alter table client_registration owner to iam_migrator;
alter table client_redirect_uri owner to iam_migrator;
alter table client_grant_type owner to iam_migrator;
alter table client_pkce_method owner to iam_migrator;
alter table resource_registration owner to iam_migrator;
alter table resource_scope owner to iam_migrator;
alter table product_security_policy owner to iam_migrator;
alter table policy_grant_type owner to iam_migrator;
alter table policy_activation_evidence owner to iam_migrator;
alter function reconcile_pinned_registration(text,smallint,text,text,text,text,text,text,text[],text[],text[],text,text,text[],boolean,text,text[]) owner to iam_migrator;
alter function canonical_registration() owner to iam_migrator;
revoke all on app_registration,client_registration,client_redirect_uri,client_grant_type,client_pkce_method,
 resource_registration,resource_scope,product_security_policy,policy_grant_type,policy_activation_evidence,
 pinned_registration_allowlist from public;
revoke all on function reconcile_pinned_registration(text,smallint,text,text,text,text,text,text,text[],text[],text[],text,text,text[],boolean,text,text[]) from public;
revoke all on function canonical_registration() from public;
grant select on app_registration,client_registration,client_redirect_uri,client_grant_type,client_pkce_method,
 resource_registration,resource_scope,product_security_policy,policy_grant_type,policy_activation_evidence to iam_runtime;
grant execute on function reconcile_pinned_registration(text,smallint,text,text,text,text,text,text,text[],text[],text[],text,text,text[],boolean,text,text[]) to iam_registration_reconciler;
grant execute on function canonical_registration() to iam_runtime;
grant usage on schema public to iam_registration_reconciler;
grant all on app_registration,client_registration,client_redirect_uri,client_grant_type,client_pkce_method,
 resource_registration,resource_scope,product_security_policy,policy_grant_type,policy_activation_evidence,
 pinned_registration_allowlist to iam_migrator;
