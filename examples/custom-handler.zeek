## Defines a custom log formatter which prints the number of log
## streams.


redef LogSchema::log_handler = function(streams: vector of Log::Stream)
	{
	print |streams|;
	};
