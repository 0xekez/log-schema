# @TEST-DOC: Simple test to verify that we correctly recurse into nested records.
# @TEST-REQUIRES: jq --version
# @TEST-EXEC: zeek $PACKAGE | jq '.conn.properties.id.properties' > output
# @TEST-EXEC: btest-diff output
