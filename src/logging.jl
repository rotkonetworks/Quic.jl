module QuicLogging

# QUIC logging levels
@enum LogLevel begin
    LOG_OFF = 0
    LOG_ERROR = 1
    LOG_WARN = 2
    LOG_INFO = 3
    LOG_DEBUG = 4
    LOG_TRACE = 5
end

# Global log level (default to OFF for library use)
const _log_level = Ref{LogLevel}(LOG_OFF)

"""
    set_log_level(level::LogLevel)

Set the global QUIC logging level.
"""
function set_log_level(level::LogLevel)
    _log_level[] = level
end

"""
    get_log_level() -> LogLevel

Get the current QUIC logging level.
"""
function get_log_level()
    return _log_level[]
end

"""
    quic_log(level::LogLevel, msg::String)

Log a message at the specified level if logging is enabled.
"""
function quic_log(level::LogLevel, msg::String)
    if _log_level[] >= level
        prefix = level == LOG_ERROR ? "ERROR" :
                 level == LOG_WARN ? "WARN" :
                 level == LOG_INFO ? "INFO" :
                 level == LOG_DEBUG ? "DEBUG" : "TRACE"
        println("[QUIC $prefix] $msg")
    end
end

# Convenience functions
log_error(msg::String) = quic_log(LOG_ERROR, msg)
log_warn(msg::String) = quic_log(LOG_WARN, msg)
log_info(msg::String) = quic_log(LOG_INFO, msg)
log_debug(msg::String) = quic_log(LOG_DEBUG, msg)
log_trace(msg::String) = quic_log(LOG_TRACE, msg)

export LogLevel, LOG_OFF, LOG_ERROR, LOG_WARN, LOG_INFO, LOG_DEBUG, LOG_TRACE
export set_log_level, get_log_level, quic_log
export log_error, log_warn, log_info, log_debug, log_trace

end # module QuicLogging
