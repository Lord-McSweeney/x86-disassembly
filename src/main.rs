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

    let (ops, _jump_targets) = parse::parse_data(&file_data, op::Bits::Bit16);

    let mut current_offset = 0;
    for op in ops {
        print!("{:#04}: ", current_offset);
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
