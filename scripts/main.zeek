module LogSchema;

export {
	global log_handler: function(streams: vector of Log::Stream) &redef;
}

function json_schema_for_record(info: record_field_table, rec: any): string {
	local schema = "{\"type\":\"object\",";

	schema +="\"properties\":{";
	local properties: vector of string;
	for (name, field in info)
		{
		# Only log the field if it will be written out.
		if (field$log)
			{
			# Recurse into nested records.
			if (starts_with(field$type_name, "record"))
				{
				const record_type = split_string(field$type_name, / /)[1];
				const fields = record_fields(record_type);
				const sub_schema = json_schema_for_record(fields, record_type);
				properties += fmt("\"%s\":%s", name, sub_schema);
				}
			else
				{
				local res = fmt("\"%s\": {", name);
				const t = field$type_name;
				res += fmt("\"type\":\"%s\"", t);
				res += "}";
				properties += res;
				}
			}
		}
	schema += join_string_vec(properties, ",");
	schema += "}"; # Properties.
        schema += "}"; # Schema.
	return schema;
}

function json_schema(streams: vector of Log::Stream): string
	{
	local res: vector of string;
	for (i in streams)
		{
		const stream = streams[i];
		const info = stream$columns;
		const fields = record_fields(info);

		const path = stream?$path ? stream$path : cat(info);

		res += fmt("\"%s\":%s", path, json_schema_for_record(fields, info));
		}
	return "{" +
                   "\"$schema\":\"https://json-schema.org/draft/2020-12/schema\"," +
	           "\"title\":\"Zeek log format schema\"," +
	           "\"type\": \"object\"," +
	           join_string_vec(res, ",") +
	        "}";
	}


redef log_handler = function(streams: vector of Log::Stream) {
	print json_schema(streams);
};

event zeek_init() &priority=-10000
	{
	local streams: vector of Log::Stream;
	for (id, stream in Log::active_streams)
		{
		streams += stream;
		}
	log_handler(streams);
	terminate();
	}
