use std::ffi::OsString;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ParsedCommand {
    Help,
    Version { json: bool },
    Doctor { json: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ParseError {
    pub(crate) json_requested: bool,
}

pub(crate) fn parse(
    arguments: impl IntoIterator<Item = OsString>,
) -> Result<ParsedCommand, ParseError> {
    let arguments: Vec<OsString> = arguments.into_iter().collect();
    let json_requested = arguments.iter().any(|argument| argument == "--json");
    let parse_error = || ParseError { json_requested };

    let Some(command) = arguments.first().and_then(|argument| argument.to_str()) else {
        return if arguments.is_empty() {
            Ok(ParsedCommand::Help)
        } else {
            Err(parse_error())
        };
    };

    match command {
        "-h" | "--help" if arguments.len() == 1 => Ok(ParsedCommand::Help),
        "--version" if arguments.len() == 1 => Ok(ParsedCommand::Version { json: false }),
        "version" => parse_leaf(
            &arguments[1..],
            |json| ParsedCommand::Version { json },
            parse_error,
        ),
        "doctor" => parse_leaf(
            &arguments[1..],
            |json| ParsedCommand::Doctor { json },
            parse_error,
        ),
        _ => Err(parse_error()),
    }
}

fn parse_leaf(
    arguments: &[OsString],
    command: impl FnOnce(bool) -> ParsedCommand,
    parse_error: impl FnOnce() -> ParseError,
) -> Result<ParsedCommand, ParseError> {
    match arguments {
        [] => Ok(command(false)),
        [flag] if flag == "--json" => Ok(command(true)),
        _ => Err(parse_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, ParseError, ParsedCommand};

    fn arguments(values: &[&str]) -> Vec<std::ffi::OsString> {
        values.iter().map(std::ffi::OsString::from).collect()
    }

    #[test]
    fn parses_only_the_bootstrap_surface() {
        assert_eq!(
            parse(arguments(&["version", "--json"])),
            Ok(ParsedCommand::Version { json: true })
        );
        assert_eq!(
            parse(arguments(&["doctor"])),
            Ok(ParsedCommand::Doctor { json: false })
        );
    }

    #[test]
    fn remembers_machine_mode_without_echoing_invalid_arguments() {
        assert_eq!(
            parse(arguments(&[
                "resource",
                "show",
                "secret-looking-value",
                "--json"
            ])),
            Err(ParseError {
                json_requested: true
            })
        );
    }
}
