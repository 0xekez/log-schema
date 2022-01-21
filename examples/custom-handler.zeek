redef LogSchema::log_handler = function(streams: vector of Log::Stream)
	{
	print streams;
	};

event zeek_init() {
	print LogSchema::log_handler;
}