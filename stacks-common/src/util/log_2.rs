#[macro_export]
macro_rules! with_dollar_sign {
  ($($body:tt)*) => {
      macro_rules! __with_dollar_sign { $($body)* }
      __with_dollar_sign!($);
  }
}

#[macro_export]
macro_rules! use_logging {
    ($tag:expr) => {
        with_dollar_sign! {
            ($d:tt) => {
              #[macro_export]
              macro_rules! log_trace {
                  ($d($d args:expr),*) => ({
                      let cur_level = $crate::util::log::get_loglevel();
                      if slog::Level::Trace.is_at_least(cur_level) {
                          slog_trace!($crate::util::log::LOGGER, #$tag, $d($d args),*)
                      }
                  })
              }

              #[macro_export]
              macro_rules! log_debug {
                  ($d($d args:expr),*) => ({
                      let cur_level = $crate::util::log::get_loglevel();
                      if slog::Level::Debug.is_at_least(cur_level) {
                          slog_debug!($crate::util::log::LOGGER, #$tag, $d($d args),*)
                      }
                  })
              }

              // .. other log macros
            }
        }
    };
}
