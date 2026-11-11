/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Handwritten wire schemas for mountd's implemented RPC operations.
 * These describe protocol data, not C ABI layouts. Top-level [ref] pointers
 * are represented by the pointee; every pointer below is [unique].
 */
#define INTEGER(name, w32, w64) \
	static const struct ndr_type name = { .kind = NDR_INTEGER, .width32 = w32, .width64 = w64 }
#define FIXED(name, size, alignment) \
	static const struct ndr_type name = { .kind = NDR_FIXED, \
		.width32 = size, .width64 = alignment }
#define POINTER(name, target) \
	static const struct ndr_type name = { .kind = NDR_POINTER, .element = &target }
#define RECORD_KIND(name, category, ...) \
	static const struct ndr_type *const name##_fields[] = { __VA_ARGS__ }; \
	static const struct ndr_type name = { .kind = category, .fields = name##_fields, \
		.count = G_N_ELEMENTS(name##_fields) }
#define RECORD(name, ...) RECORD_KIND(name, NDR_STRUCT, __VA_ARGS__)
#define PROCEDURE(name, ...) RECORD_KIND(name, NDR_PROCEDURE, __VA_ARGS__)
#define ARRAY(name, target, field, var, bound) \
	static const struct ndr_type name = { .kind = NDR_ARRAY, .element = &target, \
		.actual_field = field, .maximum_field = var ? -1 : field, \
		.divisor = 1, .limit = bound, .varying = var }
#define UNION(name, w32, w64, ...) \
	static const struct ndr_arm name##_arms[] = { __VA_ARGS__ }; \
	static const struct ndr_type name = { .kind = NDR_UNION, .width32 = w32, .width64 = w64, \
		.arms = name##_arms, .count = G_N_ELEMENTS(name##_arms) }
#define ARM(tag_value, target) { .tag = tag_value, .type = &target }
#define ARRAY_LIMIT 1048576

INTEGER(u8, 1, 1);
INTEGER(u16, 2, 2);
INTEGER(u32, 4, 4);
INTEGER(enumeration, 2, 4);
FIXED(handle, 20, 4);
FIXED(guid, 16, 4);
FIXED(timestamps, 48, 4); /* Six OLD_LARGE_INTEGER { LowPart, HighPart }. */
POINTER(p_u8, u8);
POINTER(p_u16, u16);
POINTER(p_u32, u32);
static const struct ndr_type sid = { .kind = NDR_SID };
POINTER(p_sid, sid);

static const struct ndr_type vstring = {
	.kind = NDR_ARRAY, .element = &u16, .actual_field = -1, .maximum_field = -1,
	.divisor = 1, .limit = NDR_MEMORY_LIMIT / 2, .varying = 1, .string = 1,
};
POINTER(p_vstring, vstring);
static const struct ndr_type unicode_data = {
	.kind = NDR_ARRAY, .element = &u16, .actual_field = 0, .maximum_field = 1,
	.divisor = 2, .limit = 32767, .varying = 1, .string = 2,
};
POINTER(p_unicode_data, unicode_data);
static const struct ndr_type *const unicode_fields[] = { &u16, &u16, &p_unicode_data };
static const struct ndr_type unicode = {
	.kind = NDR_STRUCT, .fields = unicode_fields, .count = 3, .unicode = 1,
};
static const struct ndr_type ansi_data = {
	.kind = NDR_ARRAY, .element = &u8, .actual_field = 0, .maximum_field = 1,
	.divisor = 1, .limit = 65535, .varying = 1,
};
POINTER(p_ansi_data, ansi_data);
RECORD(ansi, &u16, &u16, &p_ansi_data);
POINTER(p_ansi, ansi);

ARRAY(bytes_count0, u8, 0, 0, NDR_MEMORY_LIMIT);
POINTER(p_bytes_count0, bytes_count0);
RECORD(sd_buffer, &u32, &p_bytes_count0);
POINTER(p_sd_buffer, sd_buffer);
/* An ACL has its conformant byte count before the four fixed header bytes. */
static const struct ndr_type acl = { .kind = NDR_ACL };
POINTER(p_acl, acl);
RECORD(security_descriptor, &u8, &u8, &u16, &p_sid, &p_sid, &p_acl, &p_acl);
POINTER(p_security_descriptor, security_descriptor);
RECORD(qos, &u32, &enumeration, &u8, &u8);
POINTER(p_qos, qos);
RECORD(attributes, &u32, &p_u8, &p_ansi, &u32, &p_security_descriptor, &p_qos);

ARRAY(ulongs_count0, u32, 0, 0, ARRAY_LIMIT);
POINTER(p_ulongs_count0, ulongs_count0);
RECORD(ulong_buffer, &u32, &p_ulongs_count0);
ARRAY(unicode_count0, unicode, 0, 0, ARRAY_LIMIT);
POINTER(p_unicode_count0, unicode_count0);
RECORD(unicode_buffer, &u32, &p_unicode_count0);
ARRAY(sid_pointers_count0, p_sid, 0, 0, 20480);
POINTER(p_sid_pointers_count0, sid_pointers_count0);
RECORD(sid_buffer, &u32, &p_sid_pointers_count0);
RECORD(rid_name, &u32, &unicode);
ARRAY(rid_names_count0, rid_name, 0, 0, ARRAY_LIMIT);
POINTER(p_rid_names_count0, rid_names_count0);
RECORD(rid_names, &u32, &p_rid_names_count0);
POINTER(p_rid_names, rid_names);
RECORD(group_members, &u32, &p_ulongs_count0, &p_ulongs_count0);
POINTER(p_group_members, group_members);
RECORD(rid_attributes, &u32, &u32);
ARRAY(groups_count0, rid_attributes, 0, 0, ARRAY_LIMIT);
POINTER(p_groups_count0, groups_count0);
RECORD(groups, &u32, &p_groups_count0);
POINTER(p_groups, groups);

/* MS-SAMR user information classes implemented by rpc_samr.c. */
RECORD(user_general, &unicode, &unicode, &u32, &unicode, &unicode);
RECORD(user_names, &unicode, &unicode);
RECORD(user_string, &unicode);
RECORD(user_group, &u32);
static const struct ndr_type logon_bits = {
	.kind = NDR_ARRAY, .element = &u8, .actual_field = 0, .maximum_field = -1,
	.divisor = 8, .bias = 7, .limit = 1260, .varying = 1,
};
POINTER(p_logon_bits, logon_bits);
RECORD(logon_hours, &u16, &p_logon_bits);
RECORD(user_all, &timestamps,
	&unicode, &unicode, &unicode, &unicode, &unicode, &unicode, &unicode,
	&unicode, &unicode, &unicode, &unicode, &unicode, &unicode,
	&sd_buffer, &u32, &u32, &u32, &u32, &logon_hours,
	&u16, &u16, &u16, &u16, &u8, &u8, &u8, &u8);
UNION(user_info, 2, 4,
	ARM(1, user_general), ARM(6, user_names), ARM(7, user_string), ARM(8, user_string),
	ARM(9, user_group), ARM(10, user_names), ARM(11, user_string), ARM(12, user_string),
	ARM(13, user_string), ARM(14, user_string), ARM(21, user_all));
POINTER(p_user_info, user_info);
RECORD(connect_info, &u32, &u32);
UNION(connect_union, 4, 4, ARM(1, connect_info));
ARRAY(samr_names, unicode, 1, 1, 1000);
ARRAY(samr_ids, u32, 1, 1, 1000);
PROCEDURE(handle_in, &handle);
PROCEDURE(handle_out, &handle, &u32);
PROCEDURE(access_in, &handle, &u32);
PROCEDURE(open_account_in, &handle, &u32, &u32);
PROCEDURE(samr_connect_in, &p_vstring, &u32, &u32, &connect_union);
PROCEDURE(samr_connect_out, &u32, &connect_union, &handle, &u32);
PROCEDURE(samr_enum_in, &handle, &u32, &u32);
PROCEDURE(samr_users_in, &handle, &u32, &u32, &u32);
PROCEDURE(samr_enum_out, &u32, &p_rid_names, &u32, &u32);
PROCEDURE(samr_domain_in, &handle, &unicode);
PROCEDURE(samr_domain_out, &p_sid, &u32);
PROCEDURE(samr_open_domain_in, &handle, &u32, &sid);
PROCEDURE(samr_alias_in, &handle, &sid_buffer);
PROCEDURE(samr_ulongs_out, &ulong_buffer, &u32);
PROCEDURE(samr_names_in, &handle, &u32, &samr_names);
PROCEDURE(samr_names_out, &ulong_buffer, &ulong_buffer, &u32);
PROCEDURE(samr_ids_in, &handle, &u32, &samr_ids);
PROCEDURE(samr_ids_out, &unicode_buffer, &ulong_buffer, &u32);
PROCEDURE(samr_members_out, &p_group_members, &u32);
PROCEDURE(samr_alias_out, &sid_buffer, &u32);
PROCEDURE(samr_user_in, &handle, &enumeration);
PROCEDURE(samr_user_out, &p_user_info, &u32);
PROCEDURE(samr_security_out, &p_sd_buffer, &u32);
PROCEDURE(samr_groups_out, &p_groups, &u32);

/* MS-LSAD / MS-LSAT. */
RECORD(domain_info, &unicode, &p_sid);
ARRAY(domains_count0, domain_info, 0, 0, 20480);
POINTER(p_domains_count0, domains_count0);
RECORD(domain_list, &u32, &p_domains_count0, &u32);
POINTER(p_domain_list, domain_list);
UNION(policy_info, 2, 4, ARM(5, domain_info));
POINTER(p_policy_info, policy_info);
RECORD(translated_sid, &enumeration, &u32, &u32);
RECORD(translated_sid3, &enumeration, &p_sid, &u32, &u32);
RECORD(translated_name, &enumeration, &unicode, &u32);
RECORD(translated_name2, &enumeration, &unicode, &u32, &u32);
ARRAY(trans_sids_array, translated_sid, 0, 0, 20480);
POINTER(trans_sids_pointer, trans_sids_array);
RECORD(trans_sids, &u32, &trans_sids_pointer);
ARRAY(trans_sids3_array, translated_sid3, 0, 0, 20480);
POINTER(trans_sids3_pointer, trans_sids3_array);
RECORD(trans_sids3, &u32, &trans_sids3_pointer);
ARRAY(trans_names_array, translated_name, 0, 0, 20480);
POINTER(trans_names_pointer, trans_names_array);
RECORD(trans_names, &u32, &trans_names_pointer);
ARRAY(trans_names2_array, translated_name2, 0, 0, 20480);
POINTER(trans_names2_pointer, trans_names2_array);
RECORD(trans_names2, &u32, &trans_names2_pointer);
ARRAY(lsa_names, unicode, 1, 0, 1000);
PROCEDURE(lsa_open_in, &p_u16, &attributes, &u32);
PROCEDURE(lsa_open2_in, &p_vstring, &attributes, &u32);
PROCEDURE(lsa_policy_out, &p_policy_info, &u32);
PROCEDURE(lsa_names_in, &handle, &u32, &lsa_names, &trans_sids, &enumeration, &u32);
PROCEDURE(lsa_names3_in, &handle, &u32, &lsa_names, &trans_sids3, &enumeration, &u32, &u32, &u32);
PROCEDURE(lsa_names_out, &p_domain_list, &trans_sids, &u32, &u32);
PROCEDURE(lsa_names3_out, &p_domain_list, &trans_sids3, &u32, &u32);
PROCEDURE(lsa_sids_in, &handle, &sid_buffer, &trans_names, &enumeration, &u32);
PROCEDURE(lsa_sids2_in, &handle, &sid_buffer, &trans_names2, &enumeration, &u32, &u32, &u32);
PROCEDURE(lsa_sids_out, &p_domain_list, &trans_names, &u32, &u32);
PROCEDURE(lsa_sids2_out, &p_domain_list, &trans_names2, &u32, &u32);
RECORD(role_basic, &enumeration, &u32, &p_vstring, &p_vstring, &p_vstring, &guid);
UNION(role_info, 2, 4, ARM(1, role_basic));
POINTER(p_role_info, role_info);
PROCEDURE(role_in, &enumeration);
PROCEDURE(role_out, &p_role_info, &u32);

/* MS-SRVS and MS-WKST. */
RECORD(share0, &p_vstring);
RECORD(share1, &p_vstring, &u32, &p_vstring);
RECORD(share2, &p_vstring, &u32, &p_vstring, &u32, &u32, &u32, &p_vstring, &p_vstring);
ARRAY(bytes_count8, u8, 8, 0, NDR_MEMORY_LIMIT);
POINTER(p_bytes_count8, bytes_count8);
RECORD(share502, &p_vstring, &u32, &p_vstring, &u32, &u32, &u32, &p_vstring, &p_vstring,
	&u32, &p_bytes_count8);
POINTER(p_share0, share0);
ARRAY(shares0, share0, 0, 0, ARRAY_LIMIT);
POINTER(p_shares0, shares0);
RECORD(share_container0, &u32, &p_shares0);
POINTER(p_share_container0, share_container0);
POINTER(p_share1, share1);
ARRAY(shares1, share1, 0, 0, ARRAY_LIMIT);
POINTER(p_shares1, shares1);
RECORD(share_container1, &u32, &p_shares1);
POINTER(p_share_container1, share_container1);
POINTER(p_share2, share2);
ARRAY(shares2, share2, 0, 0, ARRAY_LIMIT);
POINTER(p_shares2, shares2);
RECORD(share_container2, &u32, &p_shares2);
POINTER(p_share_container2, share_container2);
POINTER(p_share502, share502);
ARRAY(shares502, share502, 0, 0, ARRAY_LIMIT);
POINTER(p_shares502, shares502);
RECORD(share_container502, &u32, &p_shares502);
POINTER(p_share_container502, share_container502);
UNION(share_union, 4, 4, ARM(0, p_share0), ARM(1, p_share1),
	ARM(2, p_share2), ARM(502, p_share502));
UNION(share_ctr_union, 4, 4, ARM(0, p_share_container0), ARM(1, p_share_container1),
	ARM(2, p_share_container2), ARM(502, p_share_container502));
RECORD(share_ctr, &u32, &share_ctr_union);
PROCEDURE(share_enum_in, &p_vstring, &share_ctr, &u32, &p_u32);
PROCEDURE(share_enum_out, &share_ctr, &u32, &p_u32, &u32);
PROCEDURE(share_get_in, &p_vstring, &vstring, &u32);
PROCEDURE(share_get_out, &share_union, &u32);
PROCEDURE(info_in, &p_vstring, &u32);
RECORD(server100, &u32, &p_vstring);
RECORD(server101, &u32, &p_vstring, &u32, &u32, &u32, &p_vstring);
RECORD(server102, &u32, &p_vstring, &u32, &u32, &u32, &p_vstring,
	&u32, &u32, &u32, &u32, &u32, &u32, &p_vstring);
RECORD(server103, &u32, &p_vstring, &u32, &u32, &u32, &p_vstring,
	&u32, &u32, &u32, &u32, &u32, &u32, &p_vstring, &u32);
POINTER(p_server100, server100);
POINTER(p_server101, server101);
POINTER(p_server102, server102);
POINTER(p_server103, server103);
UNION(server_info, 4, 4, ARM(100, p_server100), ARM(101, p_server101),
	ARM(102, p_server102), ARM(103, p_server103));
PROCEDURE(server_out, &server_info, &u32);
RECORD(workstation100, &u32, &p_vstring, &p_vstring, &u32, &u32);
RECORD(workstation101, &u32, &p_vstring, &p_vstring, &u32, &u32, &p_vstring);
RECORD(workstation102, &u32, &p_vstring, &p_vstring, &u32, &u32, &p_vstring, &u32);
POINTER(p_workstation100, workstation100);
POINTER(p_workstation101, workstation101);
POINTER(p_workstation102, workstation102);
UNION(workstation_info, 4, 4, ARM(100, p_workstation100), ARM(101, p_workstation101),
	ARM(102, p_workstation102));
PROCEDURE(workstation_out, &workstation_info, &u32);

struct ndr_operation {
	unsigned int interface, opnum;
	const struct ndr_type *request, *response;
};
#define OP(iface, number, input, output) { iface, number, &input, &output }
static const struct ndr_operation operations[] = {
	OP(1, 1, handle_in, handle_out), OP(1, 3, access_in, samr_security_out),
	OP(1, 5, samr_domain_in, samr_domain_out), OP(1, 6, samr_enum_in, samr_enum_out),
	OP(1, 7, samr_open_domain_in, handle_out), OP(1, 11, samr_enum_in, samr_enum_out),
	OP(1, 13, samr_users_in, samr_enum_out), OP(1, 15, samr_enum_in, samr_enum_out),
	OP(1, 16, samr_alias_in, samr_ulongs_out), OP(1, 17, samr_names_in, samr_names_out),
	OP(1, 18, samr_ids_in, samr_ids_out), OP(1, 19, open_account_in, handle_out),
	OP(1, 25, handle_in, samr_members_out), OP(1, 27, open_account_in, handle_out),
	OP(1, 33, handle_in, samr_alias_out), OP(1, 34, open_account_in, handle_out),
	OP(1, 36, samr_user_in, samr_user_out), OP(1, 39, handle_in, samr_groups_out),
	OP(1, 64, samr_connect_in, samr_connect_out),
	OP(2, 0, handle_in, handle_out), OP(2, 6, lsa_open_in, handle_out),
	OP(2, 7, samr_user_in, lsa_policy_out), OP(2, 14, lsa_names_in, lsa_names_out),
	OP(2, 15, lsa_sids_in, lsa_sids_out), OP(2, 44, lsa_open2_in, handle_out),
	OP(2, 57, lsa_sids2_in, lsa_sids2_out), OP(2, 68, lsa_names3_in, lsa_names3_out),
	OP(3, 0, role_in, role_out),
	OP(4, 15, share_enum_in, share_enum_out), OP(4, 16, share_get_in, share_get_out),
	OP(4, 21, info_in, server_out), OP(4, 36, share_enum_in, share_enum_out),
	OP(5, 0, info_in, workstation_out),
};

static const struct ndr_operation *ndr_operation(struct ksmbd_rpc_pipe *pipe)
{
	const struct dcerpc_syntax *syntax =
		rpc_pipe_context_syntax(pipe, pipe->dce->req_hdr.context_id);
	unsigned int interface = 0;
	size_t i;

	if (!syntax)
		return NULL;
	/* The binder has already validated the complete abstract syntax UUID. */
	if (syntax->uuid.time_low == 0x12345778)
		interface = syntax->uuid.node[5] == 0xac ? 1 : 2;
	else if (syntax->uuid.time_low == 0x3919286a)
		interface = 3;
	else if (syntax->uuid.time_low == 0x4b324fc8)
		interface = 4;
	else if (syntax->uuid.time_low == 0x6bffd098)
		interface = 5;
	for (i = 0; i < G_N_ELEMENTS(operations); i++)
		if (operations[i].interface == interface &&
		    operations[i].opnum == pipe->dce->req_hdr.opnum)
			return &operations[i];
	return NULL;
}
