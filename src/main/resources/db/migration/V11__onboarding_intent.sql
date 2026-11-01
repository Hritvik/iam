-- W-8: one logical onboarding intent per activation version, appended with its initial delivery.
create function append_onboarding_intent(p_event_id text, p_activation_id text, p_app_id text,
 p_app_subject text, p_activation_version bigint, p_onboarding_version bigint, p_reason text,
 p_environment text, p_correlation_id text, p_payload_text text, p_fingerprint text)
returns table(result text, event_id text)
language plpgsql volatile security definer set search_path=pg_catalog,public as $$
declare activation public.app_activation%rowtype; inserted integer; existing_event text;
begin
 if p_event_id is null or not p_event_id ~ '^evt_[A-Za-z0-9_-]{16,128}$'
  or p_activation_id is null or p_app_id is null or p_app_subject is null
  or p_activation_version is null or p_onboarding_version is null or p_reason is null
  or p_environment is null or p_correlation_id is null or p_payload_text is null or p_fingerprint is null
  or p_environment not in ('development','test','staging','production')
  or not p_correlation_id ~ '^cor_[A-Za-z0-9_-]{16,128}$'
  or not p_fingerprint ~ '^[0-9a-f]{64}$' then
  return query select 'REJECTED'::text,null::text; return;
 end if;
 select * into activation from public.app_activation a where a.activation_id = p_activation_id for update;
 if not found or activation.state <> 'ACTIVE'
  or (p_payload_text::jsonb->>'appSubject') is distinct from activation.app_subject
  or (p_payload_text::jsonb->>'activationVersion')::bigint is distinct from activation.activation_version
  or (p_payload_text::jsonb->>'onboardingReason') is distinct from activation.onboarding_reason
  or (p_payload_text::jsonb->>'appRegistrationId') is distinct from p_app_id
  or (p_payload_text::jsonb->>'activationId') is distinct from p_activation_id
  or (p_payload_text::jsonb->>'onboardingVersion')::bigint is distinct from p_onboarding_version
  or not exists (select 1 from public.app_registration r
                  where r.app_registration_id = p_app_id and r.environment = p_environment)
  or activation.app_registration_id <> p_app_id or activation.app_subject <> p_app_subject
  or activation.activation_version <> p_activation_version
  or activation.onboarding_version <> p_onboarding_version
  or activation.onboarding_reason <> p_reason then
  return query select 'REJECTED'::text,null::text; return;
 end if;
 insert into public.outbox_event(event_id,event_type,schema_version,occurred_at,producer,environment,
  aggregate_type,aggregate_id,aggregate_version,correlation_id,causation_id,
  destination_app_registration_id,payload,payload_fingerprint)
 values (p_event_id,'iam.app-subject.onboarding-ready.v1',1,transaction_timestamp(),'iam',p_environment,
  'APP_ONBOARDING',p_activation_id,p_onboarding_version,p_correlation_id,null,p_app_id,
  p_payload_text::jsonb,p_fingerprint)
 on conflict (producer,event_type,schema_version,aggregate_type,aggregate_id,aggregate_version,
  destination_app_registration_id) do nothing;
 get diagnostics inserted = row_count;
 if inserted = 0 then
  select e.event_id into existing_event from public.outbox_event e
   where e.aggregate_id = p_activation_id and e.aggregate_version = p_onboarding_version
     and e.destination_app_registration_id = p_app_id;
  if existing_event is null or not exists (select 1 from public.outbox_event e
      where e.event_id = existing_event and e.payload = p_payload_text::jsonb
        and e.payload_fingerprint = p_fingerprint) then
   return query select 'REJECTED'::text,null::text; return;
  end if;
  perform public.append_initial_delivery(existing_event, transaction_timestamp());
  return query select 'EXISTING'::text, existing_event; return;
 end if;
 perform public.append_initial_delivery(p_event_id, transaction_timestamp());
 return query select 'CREATED'::text, p_event_id;
exception when integrity_constraint_violation or data_exception then
 return query select 'REJECTED'::text,null::text;
end $$;

alter function append_onboarding_intent(text,text,text,text,bigint,bigint,text,text,text,text,text) owner to iam_migrator;
revoke all on function append_onboarding_intent(text,text,text,text,bigint,bigint,text,text,text,text,text) from public;
grant execute on function append_onboarding_intent(text,text,text,text,bigint,bigint,text,text,text,text,text) to iam_runtime;
