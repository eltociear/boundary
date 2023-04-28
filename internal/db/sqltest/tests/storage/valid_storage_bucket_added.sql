-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

begin;
    select plan(4);

    -- Ensure test data is correct
    select is(count(*), 2::bigint) from storage_plugin_storage_bucket;

    -- insert global storage bucket
    insert into storage_plugin_storage_bucket
    	(public_id,     scope_id, plugin_id,       bucket_name,        worker_filter,        secrets_hmac)
    values
        ('sb_________1','global', 'plg____sb-plg', 'test bucket name', 'test worker filter', '\xdeadbeef');

    select is(count(*), 1::bigint) from storage_plugin_storage_bucket where public_id = 'sb_________1';

    -- insert org storage bucket
    insert into storage_plugin_storage_bucket
    	(public_id,     scope_id,       plugin_id,       bucket_name,        worker_filter,        secrets_hmac)
    values
        ('sb_________2','o_____colors', 'plg____sb-plg', 'test bucket name', 'test worker filter', '\xdeadbeef');

    select is(count(*), 1::bigint) from storage_plugin_storage_bucket where public_id = 'sb_________2';

    -- Try to insert row with a project scope id
    prepare invalid_storage_bucket as
    insert into storage_plugin_storage_bucket
    	(public_id,     scope_id,       plugin_id,       bucket_name,        worker_filter,        secrets_hmac)
    values
        ('sb_________3','p____bcolors', 'plg____sb-plg', 'test bucket name', 'test worker filter', '\xdeadbeef');
    select throws_ok('invalid_storage_bucket', null, null, 'insert invalid storage_bucket succeeded');

    select * from finish();
rollback;