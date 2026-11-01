do $$ begin
    if not exists (select 1 from pg_roles where rolname = 'iam_migrator')
       or not exists (select 1 from pg_roles where rolname = 'iam_runtime')
       or not exists (select 1 from pg_roles where rolname = 'iam_relay') then
        raise exception 'required IAM privilege roles are not provisioned';
    end if;
end $$;

create function jsonb_top_level_key_count(value jsonb) returns bigint
language sql immutable strict parallel safe
return (select count(*) from jsonb_object_keys(value));

create function onboarding_payload_valid(value jsonb, destination text, aggregate_id text, aggregate_version bigint)
returns boolean language plpgsql immutable strict parallel safe as $$
begin
    return jsonb_typeof(value) = 'object' and jsonb_top_level_key_count(value) = 8
      and (value->>'appRegistrationId') ~ '^[a-z][a-z0-9-]{2,63}$'
      and (value->>'appSubject') ~ '^aps_[A-Za-z0-9_-]{22,128}$'
      and (value->>'activationId') ~ '^act_[A-Za-z0-9_-]{16,128}$'
      and value->>'activationState' = 'ACTIVE'
      and value->>'activationVersion' ~ '^[1-9][0-9]*$'
      and value->>'onboardingReason' in ('FIRST_ACTIVATION','RECONCILIATION')
      and value->>'onboardingVersion' ~ '^[1-9][0-9]*$'
      and value->>'requiredProfileState' = 'PROFILE_REQUIRED'
      and value->>'appRegistrationId' = destination
      and value->>'activationId' = aggregate_id
      and (value->>'onboardingVersion')::bigint = aggregate_version;
exception when others then
    return false;
end $$;

create table outbox_event (
    event_id text primary key check (event_id ~ '^evt_[A-Za-z0-9_-]{16,128}$'),
    event_type text not null check (event_type = 'iam.app-subject.onboarding-ready.v1'),
    schema_version bigint not null check (schema_version = 1),
    occurred_at timestamptz not null,
    producer text not null check (producer = 'iam'),
    environment text not null check (environment in ('development','test','staging','production')),
    aggregate_type text not null check (aggregate_type = 'APP_ONBOARDING'),
    aggregate_id text not null check (aggregate_id ~ '^[A-Za-z][A-Za-z0-9_-]{2,128}$'),
    aggregate_version bigint not null check (aggregate_version >= 1),
    correlation_id text not null check (correlation_id ~ '^cor_[A-Za-z0-9_-]{16,128}$'),
    causation_id text check (causation_id is null or causation_id ~ '^cau_[A-Za-z0-9_-]{16,128}$'),
    destination_app_registration_id text not null check (destination_app_registration_id ~ '^[a-z][a-z0-9-]{2,63}$'),
    payload jsonb not null check (jsonb_typeof(payload) = 'object' and payload <> '{}'::jsonb and jsonb_top_level_key_count(payload) <= 32),
    payload_fingerprint char(64) not null check (payload_fingerprint ~ '^[0-9a-f]{64}$'),
    recorded_at timestamptz not null default transaction_timestamp(),
    check (onboarding_payload_valid(payload,destination_app_registration_id,aggregate_id,aggregate_version)),
    unique (producer,event_type,schema_version,aggregate_type,aggregate_id,aggregate_version,destination_app_registration_id)
);

create table event_delivery_route (
    event_type text not null,
    destination_app_registration_id text not null,
    destination_name text not null check (destination_name ~ '^[a-z][a-z0-9_-]{2,63}$'),
    primary key (event_type,destination_app_registration_id),
    unique (destination_name)
);

-- The route registry is migration-owned. Current milestone registers only Dutch UMS onboarding.
insert into event_delivery_route(event_type,destination_app_registration_id,destination_name)
values ('iam.app-subject.onboarding-ready.v1','dutch-development','dutch-ums-onboarding');

create table outbox_delivery (
    event_id text not null references outbox_event(event_id) on delete restrict,
    destination_name text not null check (destination_name ~ '^[a-z][a-z0-9_-]{2,63}$'),
    state text not null check (state in ('PENDING','LEASED','ACKNOWLEDGED','QUARANTINED')),
    attempt_count integer not null default 0 check (attempt_count >= 0),
    initial_available_at timestamptz not null,
    available_at timestamptz not null,
    lease_owner text check (lease_owner is null or lease_owner ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'),
    lease_expires_at timestamptz,
    acknowledged_at timestamptz,
    last_failure_code text check (last_failure_code is null or last_failure_code in ('RETRY_EXHAUSTED','NON_RETRYABLE_FAILURE')),
    version bigint not null default 1 check (version >= 1),
    created_at timestamptz not null default transaction_timestamp(),
    updated_at timestamptz not null default transaction_timestamp(),
    primary key (event_id,destination_name),
    check ((state = 'LEASED') = (lease_owner is not null and lease_expires_at is not null)),
    check ((state = 'ACKNOWLEDGED') = (acknowledged_at is not null)),
    check (state not in ('ACKNOWLEDGED','QUARANTINED') or (lease_owner is null and lease_expires_at is null)),
    check (state = 'QUARANTINED' or last_failure_code is null)
);

create table audit_fact (
    audit_id text primary key check (audit_id ~ '^aud_[A-Za-z0-9_-]{16,128}$'),
    fact_type text not null check (fact_type in ('OUTBOX_EVENT_RECORDED','OUTBOX_DELIVERY_QUARANTINED')),
    subject_kind text not null check (subject_kind in ('SYSTEM','APP_REGISTRATION','EVENT')),
    subject_id text,
    outcome text not null check (outcome in ('SUCCEEDED','REJECTED','FAILED')),
    correlation_id text not null check (correlation_id ~ '^cor_[A-Za-z0-9_-]{16,128}$'),
    causation_id text check (causation_id is null or causation_id ~ '^cau_[A-Za-z0-9_-]{16,128}$'),
    event_id text references outbox_event(event_id) on delete restrict,
    reason_code text check (reason_code is null or reason_code in ('RETRY_EXHAUSTED','NON_RETRYABLE_FAILURE')),
    occurred_at timestamptz not null,
    recorded_at timestamptz not null default transaction_timestamp(),
    check ((subject_kind = 'SYSTEM' and subject_id is null)
        or (subject_kind = 'APP_REGISTRATION' and subject_id ~ '^[a-z][a-z0-9-]{2,63}$')
        or (subject_kind = 'EVENT' and subject_id ~ '^evt_[A-Za-z0-9_-]{16,128}$')),
    check ((fact_type = 'OUTBOX_EVENT_RECORDED' and subject_kind = 'EVENT' and subject_id = event_id
            and event_id is not null and outcome = 'SUCCEEDED' and reason_code is null)
        or (fact_type = 'OUTBOX_DELIVERY_QUARANTINED' and subject_kind = 'EVENT' and subject_id = event_id
            and event_id is not null and outcome = 'FAILED' and reason_code is not null))
);

create function reject_immutable_fact_mutation() returns trigger language plpgsql as $$
begin raise exception 'immutable fact mutation denied' using errcode = '55000'; end $$;
create trigger outbox_event_immutable before update or delete on outbox_event
    for each row execute function reject_immutable_fact_mutation();
create trigger audit_fact_immutable before update or delete on audit_fact
    for each row execute function reject_immutable_fact_mutation();

create function append_initial_delivery(p_event_id text, p_available_at timestamptz)
returns integer language plpgsql security definer set search_path = pg_catalog, public as $$
declare inserted_count integer;
declare derived_destination text;
begin
    select r.destination_name into derived_destination
      from public.outbox_event e join public.event_delivery_route r
        on r.event_type=e.event_type
       and r.destination_app_registration_id=e.destination_app_registration_id
      where e.event_id=p_event_id;
    if derived_destination is null then
        raise exception using message = 'initial delivery rejected', errcode = '22023';
    end if;
    insert into public.outbox_delivery(event_id,destination_name,state,attempt_count,initial_available_at,available_at,
      lease_owner,lease_expires_at,acknowledged_at,last_failure_code,version)
    values (p_event_id,derived_destination,'PENDING',0,p_available_at,p_available_at,null,null,null,null,1)
    on conflict do nothing;
    get diagnostics inserted_count = row_count;
    if inserted_count = 1 then return 1; end if;
    if exists (select 1 from public.outbox_delivery where event_id=p_event_id
      and destination_name=derived_destination and initial_available_at=p_available_at) then return 0; end if;
    return -1;
exception when integrity_constraint_violation or data_exception then
    raise exception using message = 'initial delivery rejected', errcode = '22023';
end $$;

create function claim_outbox_deliveries(p_owner text, p_now timestamptz, p_lease_seconds integer,
    p_limit integer) returns setof outbox_delivery
language sql security definer set search_path = pg_catalog, public as $$
    with candidates as (
      select event_id,destination_name from public.outbox_delivery
      where p_limit between 1 and 1000 and p_owner ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'
        and p_lease_seconds between 1 and 900 and ((state = 'PENDING' and available_at <= p_now)
        or (state = 'LEASED' and lease_expires_at <= p_now))
      order by available_at,event_id,destination_name for update skip locked limit p_limit
    )
    update public.outbox_delivery d set state='LEASED',lease_owner=p_owner,
      lease_expires_at=p_now + make_interval(secs => p_lease_seconds),acknowledged_at=null,last_failure_code=null,
      attempt_count=d.attempt_count+1,version=d.version+1,updated_at=p_now
    from candidates c where d.event_id=c.event_id and d.destination_name=c.destination_name
    returning d.*
$$;

create function acknowledge_outbox_delivery(p_event_id text, p_destination_name text, p_owner text,
    p_expected_version bigint, p_now timestamptz) returns boolean
language sql security definer set search_path = pg_catalog, public as $$
    with changed as (
      update public.outbox_delivery set state='ACKNOWLEDGED',lease_owner=null,lease_expires_at=null,
        acknowledged_at=p_now,last_failure_code=null,version=version+1,updated_at=p_now
      where event_id=p_event_id and destination_name=p_destination_name and version=p_expected_version
        and state='LEASED' and lease_owner=p_owner and lease_expires_at > p_now returning 1
    ) select exists(select 1 from changed)
$$;

create function quarantine_outbox_delivery(p_event_id text, p_destination_name text, p_owner text,
    p_expected_version bigint, p_reason_code text, p_now timestamptz) returns boolean
language sql security definer set search_path = pg_catalog, public as $$
    with changed as (
      update public.outbox_delivery set state='QUARANTINED',lease_owner=null,lease_expires_at=null,
        acknowledged_at=null,last_failure_code=p_reason_code,version=version+1,updated_at=p_now
      where event_id=p_event_id and destination_name=p_destination_name and version=p_expected_version
        and state='LEASED' and lease_owner=p_owner and lease_expires_at > p_now returning 1
    ) select exists(select 1 from changed)
$$;

create function append_audit_fact(p_audit_id text, p_fact_type text, p_subject_kind text, p_subject_id text,
    p_outcome text, p_correlation_id text, p_causation_id text, p_event_id text, p_reason_code text,
    p_occurred_at timestamptz) returns integer
language plpgsql security definer set search_path = pg_catalog, public as $$
declare inserted_count integer;
begin
    insert into public.audit_fact(audit_id,fact_type,subject_kind,subject_id,outcome,correlation_id,
      causation_id,event_id,reason_code,occurred_at)
    values (p_audit_id,p_fact_type,p_subject_kind,p_subject_id,p_outcome,p_correlation_id,
      p_causation_id,p_event_id,p_reason_code,p_occurred_at) on conflict do nothing;
    get diagnostics inserted_count = row_count;
    if inserted_count = 1 then return 1; end if;
    if exists (select 1 from public.audit_fact where audit_id=p_audit_id and fact_type=p_fact_type
      and subject_kind=p_subject_kind and subject_id is not distinct from p_subject_id and outcome=p_outcome
      and correlation_id=p_correlation_id and causation_id is not distinct from p_causation_id
      and event_id is not distinct from p_event_id and reason_code is not distinct from p_reason_code
      and occurred_at=p_occurred_at) then return 0; end if;
    return -1;
exception when integrity_constraint_violation or data_exception then
    raise exception using message = 'audit fact rejected', errcode = '22023';
end $$;

create function append_outbox_event(p_event_id text, p_event_type text, p_schema_version bigint,
    p_occurred_at timestamptz, p_producer text, p_environment text, p_aggregate_type text,
    p_aggregate_id text, p_aggregate_version bigint, p_correlation_id text, p_causation_id text,
    p_destination text, p_payload_text text, p_fingerprint text) returns integer
language plpgsql security definer set search_path = pg_catalog, public as $$
declare inserted_count integer;
begin
    insert into public.outbox_event(event_id,event_type,schema_version,occurred_at,producer,environment,
      aggregate_type,aggregate_id,aggregate_version,correlation_id,causation_id,
      destination_app_registration_id,payload,payload_fingerprint)
    values (p_event_id,p_event_type,p_schema_version,p_occurred_at,p_producer,p_environment,p_aggregate_type,
      p_aggregate_id,p_aggregate_version,p_correlation_id,p_causation_id,p_destination,p_payload_text::jsonb,p_fingerprint)
    on conflict do nothing;
    get diagnostics inserted_count = row_count;
    if inserted_count = 1 then return 1; end if;
    if exists (select 1 from public.outbox_event where event_id=p_event_id and producer=p_producer
      and event_type=p_event_type and schema_version=p_schema_version and occurred_at=p_occurred_at
      and environment=p_environment and aggregate_type=p_aggregate_type and aggregate_id=p_aggregate_id
      and aggregate_version=p_aggregate_version and correlation_id=p_correlation_id
      and causation_id is not distinct from p_causation_id and destination_app_registration_id=p_destination
      and payload=p_payload_text::jsonb and payload_fingerprint=p_fingerprint) then return 0; end if;
    return -1;
exception when integrity_constraint_violation or data_exception then
    raise exception using message = 'outbox event rejected', errcode = '22023';
end $$;

alter table outbox_event owner to iam_migrator;
alter table event_delivery_route owner to iam_migrator;
alter table outbox_delivery owner to iam_migrator;
alter table audit_fact owner to iam_migrator;
alter function jsonb_top_level_key_count(jsonb) owner to iam_migrator;
alter function onboarding_payload_valid(jsonb,text,text,bigint) owner to iam_migrator;
alter function reject_immutable_fact_mutation() owner to iam_migrator;
alter function append_initial_delivery(text,timestamptz) owner to iam_migrator;
alter function claim_outbox_deliveries(text,timestamptz,integer,integer) owner to iam_migrator;
alter function acknowledge_outbox_delivery(text,text,text,bigint,timestamptz) owner to iam_migrator;
alter function quarantine_outbox_delivery(text,text,text,bigint,text,timestamptz) owner to iam_migrator;
alter function append_audit_fact(text,text,text,text,text,text,text,text,text,timestamptz) owner to iam_migrator;
alter function append_outbox_event(text,text,bigint,timestamptz,text,text,text,text,bigint,text,text,text,text,text)
    owner to iam_migrator;

revoke all on schema public from public;
grant usage on schema public to iam_migrator,iam_runtime,iam_relay;
alter default privileges for role iam_migrator in schema public revoke all on tables from public;
alter default privileges for role iam_migrator in schema public revoke execute on functions from public;
revoke all on outbox_event,event_delivery_route,outbox_delivery,audit_fact from public;
revoke all on function jsonb_top_level_key_count(jsonb),onboarding_payload_valid(jsonb,text,text,bigint),
    reject_immutable_fact_mutation(),
    append_initial_delivery(text,timestamptz),
    claim_outbox_deliveries(text,timestamptz,integer,integer),
    acknowledge_outbox_delivery(text,text,text,bigint,timestamptz),
    quarantine_outbox_delivery(text,text,text,bigint,text,timestamptz),
    append_audit_fact(text,text,text,text,text,text,text,text,text,timestamptz),
    append_outbox_event(text,text,bigint,timestamptz,text,text,text,text,bigint,text,text,text,text,text) from public;
grant execute on function jsonb_top_level_key_count(jsonb) to iam_runtime;
grant execute on function onboarding_payload_valid(jsonb,text,text,bigint) to iam_runtime;
grant select on outbox_event to iam_runtime;
grant execute on function append_outbox_event(text,text,bigint,timestamptz,text,text,text,text,bigint,text,text,text,text,text)
    to iam_runtime;
grant execute on function append_audit_fact(text,text,text,text,text,text,text,text,text,timestamptz) to iam_runtime;
grant select on outbox_delivery to iam_runtime;
grant execute on function append_initial_delivery(text,timestamptz) to iam_runtime;
grant select on outbox_event to iam_relay;
grant select on outbox_delivery to iam_relay;
grant execute on function claim_outbox_deliveries(text,timestamptz,integer,integer),
    acknowledge_outbox_delivery(text,text,text,bigint,timestamptz),
    quarantine_outbox_delivery(text,text,text,bigint,text,timestamptz) to iam_relay;
grant all on outbox_event,event_delivery_route,outbox_delivery,audit_fact to iam_migrator;
