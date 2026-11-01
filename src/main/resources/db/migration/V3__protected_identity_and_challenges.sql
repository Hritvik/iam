create table human_identity (
    identity_id text primary key check (identity_id ~ '^hid_[A-Za-z0-9_-]{22,128}$'),
    state text not null check (state in ('ACTIVE','LOCKED','DISABLED')),
    security_version bigint not null default 1 check (security_version >= 1),
    version bigint not null default 1 check (version >= 1),
    created_at timestamptz not null default transaction_timestamp(),
    updated_at timestamptz not null default transaction_timestamp()
);

create table verified_identifier (
    identifier_id text primary key check (identifier_id ~ '^vid_[A-Za-z0-9_-]{22,128}$'),
    identity_id text not null references human_identity(identity_id) on delete restrict,
    identifier_type text not null check (identifier_type in ('EMAIL','PHONE')),
    normalization_version smallint not null check (normalization_version = 1),
    canonical_ciphertext bytea not null check (octet_length(canonical_ciphertext) > 0),
    canonical_nonce bytea not null check (octet_length(canonical_nonce) = 12),
    canonical_tag bytea not null check (octet_length(canonical_tag) = 16),
    display_ciphertext bytea not null check (octet_length(display_ciphertext) > 0),
    display_nonce bytea not null check (octet_length(display_nonce) = 12),
    display_tag bytea not null check (octet_length(display_tag) = 16),
    encryption_key_version smallint not null check (encryption_key_version >= 1),
    verified_at timestamptz not null,
    version bigint not null default 1 check (version >= 1),
    created_at timestamptz not null default transaction_timestamp(),
    updated_at timestamptz not null default transaction_timestamp(),
    unique (identity_id, identifier_type),
    unique (identifier_id, identifier_type, normalization_version)
);

create table verified_identifier_blind_index (
    identifier_id text not null,
    identifier_type text not null check (identifier_type in ('EMAIL','PHONE')),
    normalization_version smallint not null check (normalization_version = 1),
    blind_index_key_version smallint not null check (blind_index_key_version >= 1),
    blind_index bytea not null check (octet_length(blind_index) = 32),
    primary key (identifier_id, blind_index_key_version),
    foreign key (identifier_id,identifier_type,normalization_version)
      references verified_identifier(identifier_id,identifier_type,normalization_version) on delete restrict,
    unique (identifier_type,normalization_version,blind_index_key_version,blind_index)
);

create table verification_challenge (
    challenge_id text primary key check (challenge_id ~ '^vch_[A-Za-z0-9_-]{22,128}$'),
    identity_id text not null references human_identity(identity_id) on delete restrict,
    identifier_type text not null check (identifier_type in ('EMAIL','PHONE')),
    normalization_version smallint not null check (normalization_version = 1),
    canonical_ciphertext bytea not null check (octet_length(canonical_ciphertext) > 0),
    canonical_nonce bytea not null check (octet_length(canonical_nonce) = 12),
    canonical_tag bytea not null check (octet_length(canonical_tag) = 16),
    display_ciphertext bytea not null check (octet_length(display_ciphertext) > 0),
    display_nonce bytea not null check (octet_length(display_nonce) = 12),
    display_tag bytea not null check (octet_length(display_tag) = 16),
    encryption_key_version smallint not null check (encryption_key_version >= 1),
    candidate_blind_index_key_version smallint not null check (candidate_blind_index_key_version >= 1),
    candidate_blind_index bytea not null check (octet_length(candidate_blind_index) = 32),
    challenge_digest bytea not null check (octet_length(challenge_digest) = 32),
    digest_key_version smallint not null check (digest_key_version >= 1),
    state text not null check (state in ('ISSUED','SUPERSEDED','CONSUMED','EXPIRED','LOCKED')),
    attempt_count integer not null default 0 check (attempt_count >= 0),
    max_attempts integer not null check (max_attempts between 1 and 20),
    expires_at timestamptz not null,
    consumed_at timestamptz,
    superseded_at timestamptz,
    locked_at timestamptz,
    superseded_by_challenge_id text references verification_challenge(challenge_id) on delete restrict
      deferrable initially deferred,
    version bigint not null default 1 check (version >= 1),
    created_at timestamptz not null default transaction_timestamp(),
    updated_at timestamptz not null default transaction_timestamp(),
    check (expires_at > created_at),
    check (attempt_count <= max_attempts),
    check ((state='ISSUED' and attempt_count < max_attempts) or state<>'ISSUED'),
    check ((state='LOCKED' and attempt_count = max_attempts) or state<>'LOCKED'),
    check ((state='ISSUED' and consumed_at is null and superseded_at is null and locked_at is null
            and superseded_by_challenge_id is null)
        or (state='CONSUMED' and consumed_at is not null and superseded_at is null and locked_at is null
            and superseded_by_challenge_id is null)
        or (state='SUPERSEDED' and consumed_at is null and superseded_at is not null and locked_at is null
            and superseded_by_challenge_id is not null)
        or (state='EXPIRED' and consumed_at is null and superseded_at is null and locked_at is null
            and superseded_by_challenge_id is null)
        or (state='LOCKED' and consumed_at is null and superseded_at is null and locked_at is not null
            and superseded_by_challenge_id is null))
);
create unique index one_issued_challenge_per_identity_type
    on verification_challenge(identity_id,identifier_type) where state='ISSUED';

alter table audit_fact drop constraint audit_fact_fact_type_check;
alter table audit_fact drop constraint audit_fact_subject_kind_check;
alter table audit_fact drop constraint audit_fact_check;
alter table audit_fact drop constraint audit_fact_check1;
alter table audit_fact add constraint audit_fact_fact_type_check check (fact_type in
 ('OUTBOX_EVENT_RECORDED','OUTBOX_DELIVERY_QUARANTINED','IDENTITY_CREATED','IDENTIFIER_CHALLENGE_ISSUED',
  'IDENTIFIER_CHALLENGE_SUPERSEDED','IDENTIFIER_CHALLENGE_LOCKED','IDENTIFIER_VERIFIED'));
alter table audit_fact add constraint audit_fact_subject_kind_check check
 (subject_kind in ('SYSTEM','APP_REGISTRATION','EVENT','IDENTITY','VERIFICATION_CHALLENGE','VERIFIED_IDENTIFIER'));
alter table audit_fact add constraint audit_fact_subject_shape_check check (
 (subject_kind='SYSTEM' and subject_id is null) or
 (subject_kind='APP_REGISTRATION' and subject_id ~ '^[a-z][a-z0-9-]{2,63}$') or
 (subject_kind='EVENT' and subject_id ~ '^evt_[A-Za-z0-9_-]{16,128}$') or
 (subject_kind='IDENTITY' and subject_id ~ '^hid_[A-Za-z0-9_-]{22,128}$') or
 (subject_kind='VERIFICATION_CHALLENGE' and subject_id ~ '^vch_[A-Za-z0-9_-]{22,128}$') or
 (subject_kind='VERIFIED_IDENTIFIER' and subject_id ~ '^vid_[A-Za-z0-9_-]{22,128}$'));
alter table audit_fact add constraint audit_fact_semantics_check check (
 (fact_type='OUTBOX_EVENT_RECORDED' and subject_kind='EVENT' and subject_id=event_id
   and event_id is not null and outcome='SUCCEEDED' and reason_code is null) or
 (fact_type='OUTBOX_DELIVERY_QUARANTINED' and subject_kind='EVENT' and subject_id=event_id
   and event_id is not null and outcome='FAILED' and reason_code is not null) or
 (fact_type in ('IDENTITY_CREATED','IDENTIFIER_CHALLENGE_ISSUED','IDENTIFIER_CHALLENGE_SUPERSEDED',
  'IDENTIFIER_CHALLENGE_LOCKED','IDENTIFIER_VERIFIED') and event_id is null and reason_code is null
  and outcome='SUCCEEDED'));

alter table human_identity owner to iam_migrator;
alter table verified_identifier owner to iam_migrator;
alter table verified_identifier_blind_index owner to iam_migrator;
alter table verification_challenge owner to iam_migrator;

create function supersede_verification_challenge(p_challenge_id text,p_expected_version bigint,
 p_replacement_id text) returns integer language sql security definer
 set search_path=pg_catalog,public as $$
 update public.verification_challenge set state='SUPERSEDED',superseded_at=transaction_timestamp(),
 superseded_by_challenge_id=p_replacement_id,updated_at=transaction_timestamp(),version=version+1
 where challenge_id=p_challenge_id and version=p_expected_version and state='ISSUED'
 returning 1 $$;
create function expire_verification_challenge(p_challenge_id text,p_expected_version bigint)
 returns integer language sql security definer set search_path=pg_catalog,public as $$
 update public.verification_challenge set state='EXPIRED',updated_at=transaction_timestamp(),version=version+1
 where challenge_id=p_challenge_id and version=p_expected_version and state='ISSUED'
 and expires_at<=transaction_timestamp() and attempt_count<max_attempts returning 1 $$;
create function fail_verification_challenge(p_challenge_id text,p_expected_version bigint)
 returns integer language sql security definer set search_path=pg_catalog,public as $$
 update public.verification_challenge set attempt_count=attempt_count+1,
 state=case when attempt_count+1=max_attempts then 'LOCKED' else 'ISSUED' end,
 locked_at=case when attempt_count+1=max_attempts then transaction_timestamp() else null end,
 updated_at=transaction_timestamp(),version=version+1 where challenge_id=p_challenge_id and version=p_expected_version
 and state='ISSUED' and expires_at>transaction_timestamp() and attempt_count<max_attempts returning 1 $$;
create function consume_verification_challenge(p_challenge_id text,p_expected_version bigint)
 returns integer language sql security definer set search_path=pg_catalog,public as $$
 update public.verification_challenge set state='CONSUMED',consumed_at=transaction_timestamp(),
 updated_at=transaction_timestamp(),version=version+1
 where challenge_id=p_challenge_id and version=p_expected_version and state='ISSUED'
 and expires_at>transaction_timestamp() and attempt_count<max_attempts returning 1 $$;
create function increment_identity_security(p_identity_id text,p_expected_version bigint)
 returns integer language sql security definer set search_path=pg_catalog,public as $$
 update public.human_identity set security_version=security_version+1,version=version+1,
 updated_at=transaction_timestamp()
 where identity_id=p_identity_id and version=p_expected_version returning 1 $$;
create function lock_human_identity(p_identity_id text) returns bigint language sql security definer
 set search_path=pg_catalog,public as $$
 select version from public.human_identity where identity_id=p_identity_id for update $$;
create function lock_verification_challenge(p_challenge_id text) returns bigint language sql security definer
 set search_path=pg_catalog,public as $$
 select version from public.verification_challenge where challenge_id=p_challenge_id for update $$;

alter function supersede_verification_challenge(text,bigint,text) owner to iam_migrator;
alter function expire_verification_challenge(text,bigint) owner to iam_migrator;
alter function fail_verification_challenge(text,bigint) owner to iam_migrator;
alter function consume_verification_challenge(text,bigint) owner to iam_migrator;
alter function increment_identity_security(text,bigint) owner to iam_migrator;
alter function lock_human_identity(text) owner to iam_migrator;
alter function lock_verification_challenge(text) owner to iam_migrator;
revoke all on function supersede_verification_challenge(text,bigint,text),
 expire_verification_challenge(text,bigint),fail_verification_challenge(text,bigint),
 consume_verification_challenge(text,bigint),increment_identity_security(text,bigint),
 lock_human_identity(text),lock_verification_challenge(text) from public;
revoke all on human_identity,verified_identifier,verified_identifier_blind_index,verification_challenge from public;
grant select,insert on human_identity,verified_identifier,verified_identifier_blind_index,verification_challenge to iam_runtime;
grant execute on function supersede_verification_challenge(text,bigint,text),
 expire_verification_challenge(text,bigint),fail_verification_challenge(text,bigint),
 consume_verification_challenge(text,bigint),increment_identity_security(text,bigint),
 lock_human_identity(text),lock_verification_challenge(text) to iam_runtime;
grant all on human_identity,verified_identifier,verified_identifier_blind_index,verification_challenge to iam_migrator;
