pub struct Options {
    pub start_at: usize,
    pub skips_first_jump: bool,
    pub stop_after: Option<usize>,
}

pub fn parse_arguments(args: &[String]) -> Result<Options, String> {
    let mut options = Options {
        start_at: 0,
        skips_first_jump: false,
        stop_after: None,
    };

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--start-at" => {
                let param = args.get(i + 1);
                i += 1;

                if let Some(param) = param {
                    let start_at = if let Some(hex) = param.strip_prefix("0x").or_else(|| param.strip_prefix("0X")) {
                        usize::from_str_radix(hex, 16).ok()
                    } else {
                        param.parse().ok()
                    };

                    options.start_at = start_at.unwrap_or(0);
                } else {
                    return Err("missing parameter for flag --start-at".to_string());
                }
            }
            "--skip-first-jump" => {
                options.skips_first_jump = true;
            }
            "--stop-after" => {
                let param = args.get(i + 1);
                i += 1;

                if let Some(param) = param {
                    let stop_after = if let Some(hex) = param.strip_prefix("0x").or_else(|| param.strip_prefix("0X")) {
                        usize::from_str_radix(hex, 16).ok()
                    } else {
                        param.parse().ok()
                    };

                    options.stop_after = stop_after;
                } else {
                    return Err("missing parameter for flag --stop-after".to_string());
                }
            }
            other => return Err(format!("unknown flag {}", other)),
        }

        i += 1;
    }

    Ok(options)
}
