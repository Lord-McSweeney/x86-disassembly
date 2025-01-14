use std::fmt;

#[derive(Clone, Copy, Debug)]
pub enum ParseError {
    InvalidLeaMod,
    InvalidReg(u8),
    InvalidSegmentRegister(u8),
    OutOfData,
    UnimplementedMod(u8),
    UnimplementedOp(u8),
    UnimplementedReg(u8),
    UnimplementedTwoByteOp(u8),
    Unimplemented32Bit,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseError::InvalidLeaMod => write!(f, "invalid modr/m mod 3 in lea instruction"),
            ParseError::InvalidReg(reg) => write!(f, "invalid modr/m reg {}", reg),
            ParseError::InvalidSegmentRegister(num) => {
                write!(f, "invalid segment register #{}", num)
            }
            ParseError::OutOfData => write!(f, "reached end of stream"),
            ParseError::UnimplementedMod(mod_part) => {
                write!(f, "unimplemented modr/m mod {}", mod_part)
            }
            ParseError::UnimplementedOp(opcode) => {
                write!(f, "unimplemented opcode {:#04x}", opcode)
            }
            ParseError::UnimplementedReg(reg_part) => {
                write!(f, "unimplemented modr/m reg {}", reg_part)
            }
            ParseError::UnimplementedTwoByteOp(opcode) => {
                write!(f, "unimplemented twobyte opcode {:#04x}", opcode)
            }
            ParseError::Unimplemented32Bit => write!(f, "unimplemented 32-bit operation"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Op<'data> {
    pub raw_data: &'data [u8],

    pub prefixes: Vec<OpPrefix>,
    pub opcode: OpCode,
    pub operands: Vec<Operand>,
}

impl<'data> Op<'data> {
    pub fn print_with_targets(
        &self,
        valid_jump_targets: &[usize],
        current_offset: usize,
    ) -> String {
        use std::fmt::Write;

        let mut result_string = String::with_capacity(24);

        let mut raw_data = String::with_capacity(16);
        for (i, byte) in self.raw_data.iter().enumerate() {
            raw_data.push_str(&format!("{:02x}", byte));
            if i != self.raw_data.len() - 1 {
                raw_data.push_str(" ");
            }
        }

        write!(result_string, "{:53}", raw_data).unwrap();

        let mut prefixes = String::with_capacity(8);
        for prefix in &self.prefixes {
            prefixes.push_str(&format!("{}", prefix));
            // Keep a trailing space
            prefixes.push_str(" ");
        }

        write!(result_string, "{}", prefixes).unwrap();

        write!(result_string, "{}", self.opcode).unwrap();

        if matches!(self.opcode, OpCode::SpecialData) {
            write!(result_string, " ").unwrap();

            let mut data = String::with_capacity(32);
            for byte in self.raw_data {
                let cbyte = *byte as char;

                if cbyte >= '!' && cbyte <= '}' {
                    data.push(cbyte);
                } else {
                    data.push('.');
                }
            }

            write!(result_string, "{}", data).unwrap()
        } else {
            if !self.operands.is_empty() {
                write!(result_string, " ").unwrap();
            }

            let mut operands = String::with_capacity(8);
            for (i, operand) in self.operands.iter().enumerate() {
                operands.push_str(&operand.print_with_targets(valid_jump_targets, current_offset));
                if i != self.operands.len() - 1 {
                    operands.push_str(", ");
                }
            }

            write!(result_string, "{}", operands).unwrap()
        };

        result_string
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Bits {
    Bit16,
    Bit32,
}

impl Bits {
    pub fn switch_if(self, condition: bool) -> Self {
        if condition {
            match self {
                Bits::Bit16 => Bits::Bit32,
                Bits::Bit32 => Bits::Bit16,
            }
        } else {
            self
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum OpPrefix {
    AdSize,
    Cs,
    Ds,
    Es,
    Fs,
    Gs,
    OpSize,
    Rep,
    RepNz,
}

impl fmt::Display for OpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string = match self {
            OpPrefix::AdSize => "ADSIZE",
            OpPrefix::Cs => "CS",
            OpPrefix::Ds => "DS",
            OpPrefix::Es => "ES",
            OpPrefix::Fs => "FS",
            OpPrefix::Gs => "GS",
            OpPrefix::OpSize => "OPSIZE",
            OpPrefix::Rep => "REP",
            OpPrefix::RepNz => "REPNZ",
        };

        write!(f, "{}", string)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum OpCode {
    Adc,
    Add,
    And,
    Call,
    Cbw,
    Cdq,
    Clc,
    Cld,
    Cli,
    Cmp,
    CmpSb,
    Cwd,
    CwdE,
    Dec,
    Div,
    Hlt,
    Imul,
    Iret,
    Inc,
    InSb,
    Int,
    Ja,
    Jae,
    Jb,
    Jbe,
    Jcxz,
    Jg,
    Jge,
    Jl,
    Jle,
    Jns,
    Jnz,
    Jmp,
    Jz,
    Lea,
    Leave,
    LodSb,
    LodSw,
    Loop,
    LoopNz,
    Mov,
    MovSb,
    MovSd,
    MovSw,
    Movsx,
    Movzx,
    Mul,
    Neg,
    Nop,
    Not,
    Or,
    Out,
    OutSb,
    OutSw,
    Pop,
    PopA,
    Push,
    PushA,
    Rcl,
    Rcr,
    RetF,
    RetN,
    Rol,
    Ror,
    Sar,
    Sbb,
    ScaSb,
    Shl,
    Shr,
    Stc,
    Std,
    Sti,
    Sub,
    Test,
    Xchg,
    Xor,

    SpecialData,
    SpecialNotOp,
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string = match self {
            OpCode::Adc => "ADC",
            OpCode::Add => "ADD",
            OpCode::And => "AND",
            OpCode::Call => "CALL",
            OpCode::Cbw => "CBW",
            OpCode::Cdq => "CDQ",
            OpCode::Clc => "CLC",
            OpCode::Cld => "CLD",
            OpCode::Cli => "CLI",
            OpCode::Cmp => "CMP",
            OpCode::CmpSb => "CMPSB",
            OpCode::Cwd => "CWD",
            OpCode::CwdE => "CWDE",
            OpCode::Dec => "DEC",
            OpCode::Div => "DIV",
            OpCode::Hlt => "HLT",
            OpCode::Imul => "IMUL",
            OpCode::Iret => "IRET",
            OpCode::Inc => "INC",
            OpCode::InSb => "INSB",
            OpCode::Int => "INT",
            OpCode::Ja => "JA",
            OpCode::Jae => "JAE",
            OpCode::Jb => "JB",
            OpCode::Jbe => "JBE",
            OpCode::Jcxz => "JCXZ",
            OpCode::Jg => "JG",
            OpCode::Jge => "JGE",
            OpCode::Jl => "JL",
            OpCode::Jle => "JLE",
            OpCode::Jns => "JNS",
            OpCode::Jnz => "JNZ",
            OpCode::Jmp => "JMP",
            OpCode::Jz => "JZ",
            OpCode::Lea => "LEA",
            OpCode::Leave => "LEAVE",
            OpCode::LodSb => "LODSB",
            OpCode::LodSw => "LODSW",
            OpCode::Loop => "LOOP",
            OpCode::LoopNz => "LOOPNZ",
            OpCode::Mov => "MOV",
            OpCode::MovSb => "MOVSB",
            OpCode::MovSd => "MOVSD",
            OpCode::MovSw => "MOVSW",
            OpCode::Movsx => "MOVSX",
            OpCode::Movzx => "MOVZX",
            OpCode::Mul => "MUL",
            OpCode::Neg => "NEG",
            OpCode::Nop => "NOP",
            OpCode::Not => "NOT",
            OpCode::Or => "OR",
            OpCode::Out => "OUT",
            OpCode::OutSb => "OUTSB",
            OpCode::OutSw => "OUTSW",
            OpCode::Pop => "POP",
            OpCode::PopA => "POPA",
            OpCode::Push => "PUSH",
            OpCode::PushA => "PUSHA",
            OpCode::Rcl => "RCL",
            OpCode::Rcr => "RCR",
            OpCode::RetF => "RETF",
            OpCode::RetN => "RETN",
            OpCode::Rol => "ROL",
            OpCode::Ror => "ROR",
            OpCode::Sar => "SAR",
            OpCode::Sbb => "SBB",
            OpCode::ScaSb => "SCASB",
            OpCode::Shl => "SHL",
            OpCode::Shr => "SHR",
            OpCode::Stc => "STC",
            OpCode::Std => "STD",
            OpCode::Sti => "STI",
            OpCode::Sub => "SUB",
            OpCode::Test => "TEST",
            OpCode::Xchg => "XCHG",
            OpCode::Xor => "XOR",

            OpCode::SpecialData => " ;",
            OpCode::SpecialNotOp => unreachable!(),
        };

        write!(f, "{}", string)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum AddressRegisters {
    BxSi,
    BxDi,
    BpSi,
    BpDi,
    Si,
    Di,
    Bp,
    Bx,
}

impl fmt::Display for AddressRegisters {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string = match self {
            AddressRegisters::BxSi => "bx+si",
            AddressRegisters::BxDi => "bx+di",
            AddressRegisters::BpSi => "bp+si",
            AddressRegisters::BpDi => "bp+di",
            AddressRegisters::Si => "si",
            AddressRegisters::Di => "di",
            AddressRegisters::Bp => "bp",
            AddressRegisters::Bx => "bx",
        };

        write!(f, "{}", string)
    }
}

impl AddressRegisters {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0 => AddressRegisters::BxSi,
            1 => AddressRegisters::BxDi,
            2 => AddressRegisters::BpSi,
            3 => AddressRegisters::BpDi,
            4 => AddressRegisters::Si,
            5 => AddressRegisters::Di,
            6 => AddressRegisters::Bp,
            7 => AddressRegisters::Bx,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Register {
    Ax,
    Cx,
    Dx,
    Bx,
    Sp,
    Bp,
    Si,
    Di,

    EAx,
    ECx,
    EDx,
    EBx,
    ESp,
    EBp,
    ESi,
    EDi,
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string = match self {
            Register::Ax => "ax",
            Register::Cx => "cx",
            Register::Dx => "dx",
            Register::Bx => "bx",
            Register::Sp => "sp",
            Register::Bp => "bp",
            Register::Si => "si",
            Register::Di => "di",

            Register::EAx => "eax",
            Register::ECx => "ecx",
            Register::EDx => "edx",
            Register::EBx => "ebx",
            Register::ESp => "esp",
            Register::EBp => "ebp",
            Register::ESi => "esi",
            Register::EDi => "edi",
        };

        write!(f, "{}", string)
    }
}

impl Register {
    pub fn from_byte(byte: u8, bits: Bits) -> Self {
        match bits {
            Bits::Bit16 => match byte {
                0 => Register::Ax,
                1 => Register::Cx,
                2 => Register::Dx,
                3 => Register::Bx,
                4 => Register::Sp,
                5 => Register::Bp,
                6 => Register::Si,
                7 => Register::Di,
                _ => unreachable!(),
            },
            Bits::Bit32 => match byte {
                0 => Register::EAx,
                1 => Register::ECx,
                2 => Register::EDx,
                3 => Register::EBx,
                4 => Register::ESp,
                5 => Register::EBp,
                6 => Register::ESi,
                7 => Register::EDi,
                _ => unreachable!(),
            },
        }
    }
}

// There are 6 segment registers, but x86 can technically index 8
// through the 3 bits of ModR/M's reg part.
#[derive(Clone, Copy, Debug)]
pub enum SegmentRegister {
    Es,
    Cs,
    Ss,
    Ds,
    Fs,
    Gs,
}

impl fmt::Display for SegmentRegister {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string = match self {
            SegmentRegister::Es => "es",
            SegmentRegister::Cs => "cs",
            SegmentRegister::Ss => "ss",
            SegmentRegister::Ds => "ds",
            SegmentRegister::Fs => "fs",
            SegmentRegister::Gs => "gs",
        };

        write!(f, "{}", string)
    }
}

impl SegmentRegister {
    pub fn from_byte(byte: u8) -> Result<Self, ParseError> {
        Ok(match byte {
            0 => SegmentRegister::Es,
            1 => SegmentRegister::Cs,
            2 => SegmentRegister::Ss,
            3 => SegmentRegister::Ds,
            4 => SegmentRegister::Fs,
            5 => SegmentRegister::Gs,
            _ => return Err(ParseError::InvalidSegmentRegister(byte)),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SmallRegister {
    Al,
    Cl,
    Dl,
    Bl,
    Ah,
    Ch,
    Dh,
    Bh,
}

impl fmt::Display for SmallRegister {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string = match self {
            SmallRegister::Al => "al",
            SmallRegister::Cl => "cl",
            SmallRegister::Dl => "dl",
            SmallRegister::Bl => "bl",
            SmallRegister::Ah => "ah",
            SmallRegister::Ch => "ch",
            SmallRegister::Dh => "dh",
            SmallRegister::Bh => "bh",
        };

        write!(f, "{}", string)
    }
}

impl SmallRegister {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0 => SmallRegister::Al,
            1 => SmallRegister::Cl,
            2 => SmallRegister::Dl,
            3 => SmallRegister::Bl,
            4 => SmallRegister::Ah,
            5 => SmallRegister::Ch,
            6 => SmallRegister::Dh,
            7 => SmallRegister::Bh,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Operand {
    AbsoluteAddress32Byte {
        address: u32,
    },
    AbsoluteAddress32WordOrDword {
        address: u32,
        bits: Bits,
    },
    AbsoluteConstantSegmentedOffset16 {
        segment: u16,
        offset: u16,
    },
    AbsoluteConstantSegmentedOffset32 {
        segment: u16,
        offset: u32,
    },
    AbsoluteRegisterSegmentedByteAddress16 {
        register: SegmentRegister,
        address: u16,
    },
    AbsoluteRegisterSegmentedWordOrDwordAddress16 {
        register: SegmentRegister,
        address: u16,
        bits: Bits,
    },
    AbsoluteRegisterSegmentedWordOrDwordAddress32 {
        register: SegmentRegister,
        address: u32,
        bits: Bits,
    },
    Constant8 {
        value: u8,
    },
    Constant16 {
        value: u16,
    },
    Constant32 {
        value: u32,
    },
    GeneralRegisterAddressByte {
        register: Register,
        offset: i16,
    },
    GeneralRegisterAddressWordOrDword {
        register: Register,
        offset: i16,
        bits: Bits,
    },
    Register {
        register: Register,
    },
    RegistersAddressByte {
        registers: AddressRegisters,
        offset: i16,
    },
    RegistersAddressWordOrDword {
        registers: AddressRegisters,
        offset: i16,
        bits: Bits,
    },
    ScaleIndexBaseAddressingByte {
        scale: u8,
        index: Register,
        base: Register,
        offset: i32,
    },
    ScaleIndexBaseAddressingWordOrDword {
        scale: u8,
        index: Register,
        base: Register,
        offset: i32,
        bits: Bits,
    },
    SegmentRegister {
        register: SegmentRegister,
    },
    SmallRegister {
        register: SmallRegister,
    },
    RelativeOffset8 {
        offset: i8,
    },
    RelativeOffset16 {
        offset: i16,
    },
    RelativeOffset32 {
        offset: i32,
    },
}

impl Operand {
    pub fn print_with_targets(
        &self,
        valid_jump_targets: &[usize],
        current_offset: usize,
    ) -> String {
        match self {
            Operand::AbsoluteAddress32Byte { address } => {
                format!("byte [{:#010x}]", address)
            }
            Operand::AbsoluteAddress32WordOrDword { address, bits } => {
                let annotation = match bits {
                    Bits::Bit16 => "word",
                    Bits::Bit32 => "dword",
                };

                format!("{} [{:#010x}]", annotation, address)
            }
            Operand::AbsoluteConstantSegmentedOffset16 { segment, offset } => {
                format!("{:#06x}:{:#06x}", segment, offset)
            }
            Operand::AbsoluteConstantSegmentedOffset32 { segment, offset } => {
                format!("{:#06x}:{:#010x}", segment, offset)
            }
            Operand::AbsoluteRegisterSegmentedByteAddress16 { register, address } => {
                format!("byte [{}:{:#06x}]", register, address)
            }
            Operand::AbsoluteRegisterSegmentedWordOrDwordAddress16 {
                register,
                address,
                bits,
            } => {
                let annotation = match bits {
                    Bits::Bit16 => "word",
                    Bits::Bit32 => "dword",
                };

                format!("{} [{}:{:#06x}]", annotation, register, address)
            }
            Operand::AbsoluteRegisterSegmentedWordOrDwordAddress32 {
                register,
                address,
                bits,
            } => {
                let annotation = match bits {
                    Bits::Bit16 => "word",
                    Bits::Bit32 => "dword",
                };

                format!("{} [{}:{:#010x}]", annotation, register, address)
            }
            Operand::Constant8 { value } => format!("{:#04x}", value),
            Operand::Constant16 { value } => format!("{:#06x}", value),
            Operand::Constant32 { value } => format!("{:#010x}", value),
            Operand::GeneralRegisterAddressByte { register, offset } => {
                if *offset == 0 {
                    format!("byte [{}]", register)
                } else if *offset < 0 && *offset >= -0xFF {
                    format!("byte [{}-{:#04x}]", register, -offset)
                } else if *offset > 0 && *offset <= 0xFF {
                    format!("byte [{}+{:#04x}]", register, offset)
                } else if *offset < 0 {
                    format!("byte [{}-{:#06x}]", register, -offset)
                } else if *offset > 0 {
                    format!("byte [{}+{:#06x}]", register, offset)
                } else {
                    unreachable!()
                }
            }
            Operand::GeneralRegisterAddressWordOrDword {
                register,
                offset,
                bits,
            } => {
                let annotation = match bits {
                    Bits::Bit16 => "word",
                    Bits::Bit32 => "dword",
                };

                if *offset == 0 {
                    format!("{} [{}]", annotation, register)
                } else if *offset < 0 && *offset >= -0xFF {
                    format!("{} [{}-{:#04x}]", annotation, register, -offset)
                } else if *offset > 0 && *offset <= 0xFF {
                    format!("{} [{}+{:#04x}]", annotation, register, offset)
                } else if *offset < 0 {
                    format!("{} [{}-{:#06x}]", annotation, register, -offset)
                } else if *offset > 0 {
                    format!("{} [{}+{:#06x}]", annotation, register, offset)
                } else {
                    unreachable!()
                }
            }
            Operand::Register { register } => format!("{}", register),
            Operand::RegistersAddressByte { registers, offset } => {
                if *offset == 0 {
                    format!("byte [{}]", registers)
                } else if *offset < 0 && *offset >= -0xFF {
                    format!("byte [{}-{:#04x}]", registers, -offset)
                } else if *offset > 0 && *offset <= 0xFF {
                    format!("byte [{}+{:#04x}]", registers, offset)
                } else if *offset < 0 {
                    format!("byte [{}-{:#06x}]", registers, -offset)
                } else if *offset > 0 {
                    format!("byte [{}+{:#06x}]", registers, offset)
                } else {
                    unreachable!()
                }
            }
            Operand::RegistersAddressWordOrDword {
                registers,
                offset,
                bits,
            } => {
                let annotation = match bits {
                    Bits::Bit16 => "word",
                    Bits::Bit32 => "dword",
                };

                if *offset == 0 {
                    format!("{} [{}]", annotation, registers)
                } else if *offset < 0 && *offset >= -0xFF {
                    format!("{} [{}-{:#04x}]", annotation, registers, -offset)
                } else if *offset > 0 && *offset <= 0xFF {
                    format!("{} [{}+{:#04x}]", annotation, registers, offset)
                } else if *offset < 0 {
                    format!("{} [{}-{:#06x}]", annotation, registers, -offset)
                } else if *offset > 0 {
                    format!("{} [{}+{:#06x}]", annotation, registers, offset)
                } else {
                    unreachable!()
                }
            }
            Operand::ScaleIndexBaseAddressingByte {
                scale,
                index,
                base,
                offset,
            } => {
                let real_scale = match scale {
                    0 => 1,
                    1 => 2,
                    2 => 4,
                    3 => 8,
                    _ => unreachable!(),
                };

                let scale_index_base = if matches!(index, Register::ESp) {
                    // When the index register is ESP, it is ignored
                    // (apparently zero), and only the base register
                    // is taken into account.
                    format!("{}", base)
                } else {
                    if real_scale == 1 {
                        format!("{}+{}", index, base)
                    } else {
                        format!("{}*{}+{}", real_scale, index, base)
                    }
                };

                if *offset == 0 {
                    format!("byte [{}]", scale_index_base)
                } else if *offset < 0 && *offset >= -0xFF {
                    format!("byte [{}-{:#04x}]", scale_index_base, -offset)
                } else if *offset > 0 && *offset <= 0xFF {
                    format!("byte [{}+{:#04x}]", scale_index_base, offset)
                } else if *offset < 0 {
                    format!("byte [{}-{:#010x}]", scale_index_base, -offset)
                } else if *offset > 0 {
                    format!("byte [{}+{:#010x}]", scale_index_base, offset)
                } else {
                    unreachable!()
                }
            }
            Operand::ScaleIndexBaseAddressingWordOrDword {
                scale,
                index,
                base,
                offset,
                bits,
            } => {
                let annotation = match bits {
                    Bits::Bit16 => "word",
                    Bits::Bit32 => "dword",
                };

                let real_scale = match scale {
                    0 => 1,
                    1 => 2,
                    2 => 4,
                    3 => 8,
                    _ => unreachable!(),
                };

                let scale_index_base = if matches!(index, Register::ESp) {
                    // When the index register is ESP, it is ignored
                    // (apparently zero), and only the base register
                    // is taken into account.
                    format!("{}", base)
                } else {
                    if real_scale == 1 {
                        format!("{}+{}", index, base)
                    } else {
                        format!("{}*{}+{}", real_scale, index, base)
                    }
                };

                if *offset == 0 {
                    format!("{} [{}]", annotation, scale_index_base)
                } else if *offset < 0 && *offset >= -0xFF {
                    format!("{} [{}-{:#04x}]", annotation, scale_index_base, -offset)
                } else if *offset > 0 && *offset <= 0xFF {
                    format!("{} [{}+{:#04x}]", annotation, scale_index_base, offset)
                } else if *offset < 0 {
                    format!("{} [{}-{:#010x}]", annotation, scale_index_base, -offset)
                } else if *offset > 0 {
                    format!("{} [{}+{:#010x}]", annotation, scale_index_base, offset)
                } else {
                    unreachable!()
                }
            }
            Operand::SegmentRegister { register } => format!("{}", register),
            Operand::SmallRegister { register } => format!("{}", register),
            Operand::RelativeOffset8 { offset } => {
                let target_pos = current_offset as isize + *offset as isize;

                if valid_jump_targets.iter().any(|t| *t == target_pos as usize) {
                    if target_pos <= 0xFFFF {
                        format!("addr_{:04x}", target_pos)
                    } else {
                        format!("addr_{:08x}", target_pos)
                    }
                } else if *offset > 0 {
                    format!("+{:#04x}", offset)
                } else {
                    format!("-{:#04x}", -offset)
                }
            }
            Operand::RelativeOffset16 { offset } => {
                let target_pos = current_offset as isize + *offset as isize;

                if valid_jump_targets.iter().any(|t| *t == target_pos as usize) {
                    if target_pos <= 0xFFFF {
                        format!("addr_{:04x}", target_pos)
                    } else {
                        format!("addr_{:08x}", target_pos)
                    }
                } else if *offset > 0 {
                    format!("+{:#06x}", offset)
                } else {
                    format!("-{:#06x}", -offset)
                }
            }
            Operand::RelativeOffset32 { offset } => {
                let target_pos = current_offset as isize + *offset as isize;

                if valid_jump_targets.iter().any(|t| *t == target_pos as usize) {
                    if target_pos <= 0xFFFF {
                        format!("addr_{:04x}", target_pos)
                    } else {
                        format!("addr_{:08x}", target_pos)
                    }
                } else if *offset > 0 {
                    format!("+{:#010x}", offset)
                } else {
                    format!("-{:#010x}", -offset)
                }
            }
        }
    }
}
