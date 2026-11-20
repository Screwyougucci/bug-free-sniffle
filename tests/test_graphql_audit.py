from darthscanner.graphql_audit import discover_graphql_operations, inspect_graphql_introspection


def test_discovers_graphql_operations_without_retaining_query_values():
    source = """
    const q = gql`query AccountOverview { account(id: "private-id") { email } }`;
    const m = `mutation ChangeRole($role: String!) { updateUser(role: $role) { id } }`;
    """
    items = discover_graphql_operations("https://app.example/assets/app.js", source)
    assert [item["operation_type"] for item in items] == ["query", "mutation"]
    assert items[0]["operation_name"] == "AccountOverview"
    assert "private-id" not in str(items)
    assert "email" in items[0]["root_field_names"]


def test_introspection_flags_sensitive_mutation_arguments_and_unbounded_list():
    doc = {"data": {"__schema": {"types": [
        {"name": "Mutation", "fields": [{"name": "updateUser", "args": [
            {"name": "userId"}, {"name": "role"}]}]},
        {"name": "Query", "fields": [{"name": "allUsers", "args": [],
            "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "User"}}}]}
    ]}}}
    findings = inspect_graphql_introspection(doc, "https://app.example/graphql")
    assert any("sensitive arguments" in f.title for f in findings)
    assert any("no pagination" in f.title for f in findings)


def test_pagination_and_non_sensitive_mutation_are_not_flagged():
    doc = {"data": {"__schema": {"types": [
        {"name": "Mutation", "fields": [{"name": "rename", "args": [{"name": "displayName"}]}]},
        {"name": "Query", "fields": [{"name": "users", "args": [{"name": "first"}],
            "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "User"}}}]}
    ]}}}
    assert inspect_graphql_introspection(doc, "https://app.example/graphql") == []
