create table iam_schema_marker (
    singleton boolean primary key default true check (singleton),
    description text not null,
    installed_at timestamptz not null default transaction_timestamp()
);

insert into iam_schema_marker (description)
values ('identity platform foundation');

