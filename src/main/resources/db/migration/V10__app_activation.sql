-- W-8: strict Dutch activation. Only PENDING_PREREQUISITES -> ACTIVE is exercised in this milestone.
create table app_activation (
    activation_id text primary key check (activation_id ~ '^act_[A-Za-z0-9_-]{16,128}$'),
    app_registration_id text not null references app_registration(app_registration_id) on delete restrict,
    human_identity_id text not null references human_identity(identity_id) on delete restrict,
    app_subject text not null check (app_subject ~ '^aps_[A-Za-z0-9_-]{22,128}$'),
    state text not null check (state in ('PENDING_PREREQUISITES','ACTIVE','SUSPENDED','DEPARTED')),
    activation_version bigint not null check (activation_version >= 1),
    onboarding_version bigint not null check (onboarding_version >= 0),
    onboarding_reason text check (onboarding_reason is null or onboarding_reason in ('FIRST_ACTIVATION','RECONCILIATION')),
    created_at timestamptz not null default transaction_timestamp(),
    updated_at timestamptz not null default transaction_timestamp(),
    unique (app_registration_id, human_identity_id),
    unique (app_registration_id, app_subject),
    foreign key (app_registration_id, human_identity_id)
        references app_subject(app_registration_id, human_identity_id) on delete restrict,
    foreign key (app_registration_id, app_subject)
        references app_subject(app_registration_id, app_subject) on delete restrict,
    constraint app_activation_onboarding_coherence check (
        (state = 'ACTIVE' and onboarding_version >= 1 and onboarding_reason is not null)
        or (state <> 'ACTIVE' and onboarding_version = 0 and onboarding_reason is null))
);

create function evaluate_activation_prerequisites(p_app_registration_id text, p_human_identity_id text)
returns table(satisfied boolean, missing text[])
language plpgsql stable security definer set search_path=pg_catalog,public as $$
declare required_evidence text[]; missing_evidence text[] := '{}'::text[]; evidence text;
begin
 if p_app_registration_id is null or p_human_identity_id is null then
  return query select false, array['invalid_context']::text[]; return;
 end if;
 select array_agg(e.evidence_type order by e.evidence_type) into required_evidence
  from public.policy_activation_evidence e where e.app_registration_id = p_app_registration_id;
 if required_evidence is null then
  return query select false, array['app_not_registered']::text[]; return;
 end if;
 foreach evidence in array required_evidence loop
  if evidence = 'verified_identifier' and not exists (
      select 1 from public.verified_identifier v where v.identity_id = p_human_identity_id) then
   missing_evidence := missing_evidence || evidence;
  elsif evidence = 'usable_factor' and not exists (
      select 1 from public.authentication_factor f
       where f.identity_id = p_human_identity_id and f.state = 'ACTIVE') then
   missing_evidence := missing_evidence || evidence;
  elsif evidence = 'recovery_path' and not exists (
      select 1 from public.recovery_method r
       where r.identity_id = p_human_identity_id and r.state = 'ACTIVE') then
   missing_evidence := missing_evidence || evidence;
  end if;
 end loop;
 if not exists (select 1 from public.app_subject s
                 where s.app_registration_id = p_app_registration_id
                   and s.human_identity_id = p_human_identity_id) then
  missing_evidence := missing_evidence || 'app_subject';
 end if;
 return query select cardinality(missing_evidence) = 0, missing_evidence;
end $$;

create function read_activation_evidence(p_app_registration_id text, p_human_identity_id text)
returns table(verified_identifier boolean, usable_factor boolean, recovery_path boolean,
 app_subject_present boolean, required_evidence text[])
language plpgsql stable security definer set search_path=pg_catalog,public as $$
begin
 if p_app_registration_id is null or p_human_identity_id is null then
  return query select false,false,false,false,array[]::text[]; return;
 end if;
 return query select
  exists(select 1 from public.verified_identifier v where v.identity_id = p_human_identity_id),
  exists(select 1 from public.authentication_factor f
          where f.identity_id = p_human_identity_id and f.state = 'ACTIVE'),
  exists(select 1 from public.recovery_method r
          where r.identity_id = p_human_identity_id and r.state = 'ACTIVE'),
  exists(select 1 from public.app_subject s
          where s.app_registration_id = p_app_registration_id and s.human_identity_id = p_human_identity_id),
  coalesce((select array_agg(e.evidence_type order by e.evidence_type)
            from public.policy_activation_evidence e
            where e.app_registration_id = p_app_registration_id), array[]::text[]);
end $$;

create function advance_app_activation(p_activation_id text, p_app_registration_id text,
 p_human_identity_id text, p_app_subject text, p_expected_version bigint, p_correlation_id text)
returns table(result text, activation_id text, state text, activation_version bigint,
 onboarding_version bigint, onboarding_reason text)
language plpgsql volatile security definer set search_path=pg_catalog,public as $$
declare current_row public.app_activation%rowtype; prerequisites record; next_state text; next_onboarding bigint;
 next_reason text;
begin
 if p_activation_id is null or p_app_registration_id is null or p_human_identity_id is null
  or p_app_subject is null or p_correlation_id is null or p_expected_version is null
  or p_expected_version < 0 then
  return query select 'REJECTED'::text,null::text,null::text,null::bigint,null::bigint,null::text; return;
 end if;
 if not exists (select 1 from public.app_subject s
                 where s.app_registration_id = p_app_registration_id
                   and s.human_identity_id = p_human_identity_id
                   and s.app_subject = p_app_subject) then
  return query select 'REJECTED'::text,null::text,null::text,null::bigint,null::bigint,null::text; return;
 end if;
 perform pg_advisory_xact_lock(hashtextextended(
  'activation|' || p_app_registration_id || '|' || p_human_identity_id, 0));
 select * into current_row from public.app_activation a
  where a.app_registration_id = p_app_registration_id and a.human_identity_id = p_human_identity_id for update;
 if not found then
  if p_expected_version <> 0 then
   return query select 'CONFLICT'::text,null::text,null::text,null::bigint,null::bigint,null::text; return;
  end if;
  select * into prerequisites from public.evaluate_activation_prerequisites(
   p_app_registration_id, p_human_identity_id);
  next_state := case when prerequisites.satisfied then 'ACTIVE' else 'PENDING_PREREQUISITES' end;
  next_onboarding := case when next_state = 'ACTIVE' then 1 else 0 end;
  next_reason := case when next_state = 'ACTIVE' then 'FIRST_ACTIVATION' else null end;
  insert into public.app_activation(activation_id, app_registration_id, human_identity_id, app_subject,
   state, activation_version, onboarding_version, onboarding_reason)
  values (p_activation_id, p_app_registration_id, p_human_identity_id, p_app_subject, next_state, 1,
   next_onboarding, next_reason);
  return query select 'CREATED'::text, a.activation_id, a.state, a.activation_version, a.onboarding_version,
   a.onboarding_reason from public.app_activation a where a.activation_id = p_activation_id;
  return;
 end if;
 if current_row.app_subject <> p_app_subject then
  return query select 'REJECTED'::text,null::text,null::text,null::bigint,null::bigint,null::text; return;
 end if;
 if p_expected_version <> current_row.activation_version then
  return query select 'CONFLICT'::text,null::text,null::text,null::bigint,null::bigint,null::text; return;
 end if;
 if current_row.state = 'ACTIVE' then
  return query select 'EXISTING'::text, a.activation_id, a.state, a.activation_version, a.onboarding_version,
   a.onboarding_reason from public.app_activation a where a.activation_id = current_row.activation_id;
  return;
 end if;
 if current_row.state <> 'PENDING_PREREQUISITES' then
  return query select 'REJECTED'::text,null::text,null::text,null::bigint,null::bigint,null::text; return;
 end if;
 select * into prerequisites from public.evaluate_activation_prerequisites(
  p_app_registration_id, p_human_identity_id);
 if not prerequisites.satisfied then
  return query select 'PENDING'::text, a.activation_id, a.state, a.activation_version, a.onboarding_version,
   a.onboarding_reason from public.app_activation a where a.activation_id = current_row.activation_id;
  return;
 end if;
 update public.app_activation a
  set state = 'ACTIVE', activation_version = a.activation_version + 1, onboarding_version = 1,
      onboarding_reason = 'FIRST_ACTIVATION', updated_at = transaction_timestamp()
  where a.activation_id = current_row.activation_id
  returning * into current_row;
 return query select 'ACTIVATED'::text, current_row.activation_id, current_row.state,
  current_row.activation_version, current_row.onboarding_version, current_row.onboarding_reason;
end $$;

create function read_app_activation(p_app_registration_id text, p_human_identity_id text)
returns table(activation_id text, state text, activation_version bigint, onboarding_version bigint,
 onboarding_reason text)
language plpgsql stable security definer set search_path=pg_catalog,public as $$
begin
 if p_app_registration_id is null or p_human_identity_id is null then return; end if;
 return query select a.activation_id, a.state, a.activation_version, a.onboarding_version, a.onboarding_reason
  from public.app_activation a
  where a.app_registration_id = p_app_registration_id and a.human_identity_id = p_human_identity_id;
end $$;

alter table app_activation owner to iam_migrator;
alter function evaluate_activation_prerequisites(text,text) owner to iam_migrator;
alter function read_activation_evidence(text,text) owner to iam_migrator;
alter function advance_app_activation(text,text,text,text,bigint,text) owner to iam_migrator;
alter function read_app_activation(text,text) owner to iam_migrator;
revoke all on app_activation from public;
revoke all on function evaluate_activation_prerequisites(text,text) from public;
revoke all on function read_activation_evidence(text,text) from public;
revoke all on function advance_app_activation(text,text,text,text,bigint,text) from public;
revoke all on function read_app_activation(text,text) from public;
grant execute on function evaluate_activation_prerequisites(text,text) to iam_runtime;
grant execute on function read_activation_evidence(text,text) to iam_runtime;
grant execute on function advance_app_activation(text,text,text,text,bigint,text) to iam_runtime;
grant execute on function read_app_activation(text,text) to iam_runtime;
grant all on app_activation to iam_migrator;
