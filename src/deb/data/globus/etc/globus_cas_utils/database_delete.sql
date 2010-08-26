-- Clean up before running tests
delete from object_table;
delete from object_group_entry;
delete from object_group_table;
delete from namespace_table;
delete from user_group_entry;
delete from user_group_table;
delete from user_table;
delete from trust_anchor_table;
delete from service_action_group_entry;
delete from service_action_group;
delete from service_type_action;
delete from service_type;
delete from policy_table;
drop sequence service_action_seq;
drop sequence object_seq;	
drop sequence policy_seq	;
create sequence service_action_seq;
create sequence object_seq;	
create sequence policy_seq;	