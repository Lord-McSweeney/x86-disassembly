mod arguments;
mod op;
mod parse;

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let Some(file) = args.get(1) else {
        eprintln!("Run as {} [file] [options]", args[0]);

        std::process::exit(1);
    };

    let file_data = if let Ok(data) = std::fs::read(file) {
        data
    } else {
        eprintln!("Failed to read file");

        std::process::exit(1);
    };

    let options = match arguments::parse_arguments(&args[2..]) {
        Ok(options) => options,
        Err(e) => {
            eprintln!("Failed to parse options: {}", e);

            std::process::exit(1);
        }
    };

    let (ops, jump_targets) = parse::parse_data(&file_data, options, op::Bits::Bit16);

    let mut current_offset = 0;
    println!("                                                       start:");
    for op in ops {
        if jump_targets.iter().any(|t| *t >= 0 && (*t as usize) == current_offset) {
            println!("\n                                                       addr_{:04x}:", current_offset);
        }
        print!("{:04x}: ", current_offset);
        match op {
            Ok(op) => {
                current_offset += op.raw_data.len();
                println!("{}", op);
            }
            Err(err) => {
                println!("(error) {}", err);
                break;
            }
        }
    }

    std::process::exit(0);
}
