-- W-9 follow-up: the relay may record the immutable quarantine audit fact.
grant execute on function append_audit_fact(text,text,text,text,text,text,text,text,text,timestamp with time zone)
    to iam_relay;
