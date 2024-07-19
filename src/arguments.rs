pub struct Options {
    pub stop_after: Option<usize>,
}

pub fn parse_arguments(args: &[String]) -> Result<Options, String> {
    let mut default_options = Options {
        stop_after: None,
    };
    println!("{:?}", args);
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--stop-after" => {
                let param = args.get(i + 1);
                i += 1;

                if let Some(param) = param {
                    let stop_after = if let Some(hex) = param.strip_prefix("0x").or_else(|| param.strip_prefix("0X")) {
                        usize::from_str_radix(hex, 16).ok()
                    } else {
                        param.parse().ok()
                    };

                    default_options.stop_after = stop_after;
                } else {
                    return Err("missing parameter for flag --stop-after".to_string());
                }
            }
            other => return Err(format!("unknown flag {}", other)),
        }

        i += 1;
    }

    Ok(default_options)
}
