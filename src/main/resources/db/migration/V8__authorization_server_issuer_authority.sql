do $$ begin
 if not exists(select 1 from pg_roles where rolname='iam_migrator')
    or not exists(select 1 from pg_roles where rolname='iam_runtime') then
  raise exception 'required IAM privilege roles are not provisioned';
 end if;
end $$;

create function read_authorization_server_issuer() returns text
language plpgsql stable security definer set search_path=pg_catalog,public as $$
declare v_count bigint; v_issuer text;
begin
 select count(*),min(i.issuer) into v_count,v_issuer from public.authorization_server_issuer i;
 if v_count<>1 or v_issuer<>'https://iam.distracted.invalid' then
  raise exception 'authorization_server_issuer_unavailable';
 end if;
 return v_issuer;
end $$;

alter function read_authorization_server_issuer() owner to iam_migrator;
revoke all on function read_authorization_server_issuer() from public;
grant execute on function read_authorization_server_issuer() to iam_runtime;
