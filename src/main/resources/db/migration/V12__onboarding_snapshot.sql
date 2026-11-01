-- W-9: bounded, app-scoped, keyset-paged onboarding snapshot for a registered workload.
create function read_onboarding_snapshot(p_app_registration_id text, p_after_app_subject text, p_limit integer)
returns table(app_subject text, activation_id text, activation_state text, activation_version bigint,
 onboarding_reason text, onboarding_version bigint, required_profile_state text)
language plpgsql stable security definer set search_path=pg_catalog,public as $$
begin
 if p_app_registration_id is null or not p_app_registration_id ~ '^[a-z][a-z0-9-]{2,63}$'
  or p_limit is null or p_limit not between 1 and 201
  or (p_after_app_subject is not null and not p_after_app_subject ~ '^aps_[A-Za-z0-9_-]{24}$') then
  return;
 end if;
 return query
  select a.app_subject, a.activation_id, a.state, a.activation_version, a.onboarding_reason,
         a.onboarding_version, 'PROFILE_REQUIRED'::text
  from public.app_activation a
  where a.app_registration_id = p_app_registration_id
    and a.state = 'ACTIVE'
    and (p_after_app_subject is null or a.app_subject > p_after_app_subject)
  order by a.app_subject
  limit p_limit;
end $$;

alter function read_onboarding_snapshot(text,text,integer) owner to iam_migrator;
revoke all on function read_onboarding_snapshot(text,text,integer) from public;
grant execute on function read_onboarding_snapshot(text,text,integer) to iam_runtime;
