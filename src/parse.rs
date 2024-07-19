use crate::arguments::Options;
use crate::op::{
    AddressRegisters,
    Bits,
    Op,
    Operand,
    OpCode,
    OpPrefix,
    ParseError,
    Register,
    SegmentRegister,
    SmallRegister,
};

struct X86ByteStream<'data> {
    bytes: &'data [u8],
    pos: usize,
}

impl<'data> X86ByteStream<'data> {
    fn new(bytes: &'data[u8]) -> Self {
        Self {
            bytes,
            pos: 0,
        }
    }

    fn read_u8(&mut self) -> Result<u8, ParseError> {
        if self.pos >= self.bytes.len() {
            Err(ParseError::OutOfData)
        } else {
            let byte = self.bytes[self.pos];
            self.pos += 1;
            Ok(byte)
        }
    }

    fn read_u16(&mut self) -> Result<u16, ParseError> {
        if self.pos + 1 >= self.bytes.len() {
            Err(ParseError::OutOfData)
        } else {
            let byte1 = self.bytes[self.pos] as u16;
            let byte2 = (self.bytes[self.pos + 1] as u16) << 8;

            let result = byte1 + byte2;
            self.pos += 2;
            Ok(result)
        }
    }

    fn read_u32(&mut self) -> Result<u32, ParseError> {
        if self.pos + 3 >= self.bytes.len() {
            Err(ParseError::OutOfData)
        } else {
            let byte1 = self.bytes[self.pos] as u32;
            let byte2 = (self.bytes[self.pos + 1] as u32) << 8;
            let byte3 = (self.bytes[self.pos + 2] as u32) << 16;
            let byte4 = (self.bytes[self.pos + 3] as u32) << 24;

            let result = byte1 + byte2 + byte3 + byte4;
            self.pos += 4;
            Ok(result)
        }
    }

    fn read_i8(&mut self) -> Result<i8, ParseError> {
        if self.pos >= self.bytes.len() {
            Err(ParseError::OutOfData)
        } else {
            let result = self.bytes[self.pos] as i8;
            self.pos += 1;
            Ok(result)
        }
    }

    fn read_i16(&mut self) -> Result<i16, ParseError> {
        if self.pos + 1 >= self.bytes.len() {
            Err(ParseError::OutOfData)
        } else {
            let byte1 = self.bytes[self.pos] as u16;
            let byte2 = (self.bytes[self.pos + 1] as u16) << 8;

            let result = (byte1 + byte2) as i16;
            self.pos += 2;
            Ok(result)
        }
    }

    fn read_i32(&mut self) -> Result<i32, ParseError> {
        if self.pos + 3 >= self.bytes.len() {
            Err(ParseError::OutOfData)
        } else {
            let byte1 = self.bytes[self.pos] as u32;
            let byte2 = (self.bytes[self.pos + 1] as u32) << 8;
            let byte3 = (self.bytes[self.pos + 2] as u32) << 16;
            let byte4 = (self.bytes[self.pos + 3] as u32) << 24;

            let result = (byte1 + byte2 + byte3 + byte4) as i32;
            self.pos += 4;
            Ok(result)
        }
    }

    // See https://wiki.osdev.org/X86-64_Instruction_Encoding#16-bit_addressing
    fn read_modrm(&mut self) -> Result<(u8, u8, u8), ParseError> {
        let byte = self.read_u8()?;

        let mod_part = byte >> 6;
        let reg_part = (byte >> 3) & 0x7;
        let r_m_part = byte & 0x7;

        Ok((mod_part, reg_part, r_m_part))
    }

    fn read_mod0_operand_8bit_result(
        &mut self,
        rm: u8,
        address_bits: Bits
    ) -> Result<Operand, ParseError> {
        match address_bits {
            Bits::Bit16 => {
                match rm {
                    6 => Ok(Operand::AbsoluteRegisterSegmentedByteAddress16 {
                        register: SegmentRegister::Ds,
                        address: self.read_u16()?,
                    }),
                    _ => Ok(Operand::RegistersAddressByte {
                        registers: AddressRegisters::from_byte(rm),
                        offset: 0,
                    })
                }
            }
            Bits::Bit32 => Err(ParseError::Unimplemented32Bit)
        }
    }

    fn read_mod0_operand_16bit_result(
        &mut self,
        rm: u8,
        operand_bits: Bits,
        address_bits: Bits,
    ) -> Result<Operand, ParseError> {
        match address_bits {
            Bits::Bit16 => {
                match rm {
                    6 => Ok(Operand::AbsoluteRegisterSegmentedWordOrDwordAddress16 {
                        register: SegmentRegister::Ds,
                        address: self.read_u16()?,
                        bits: operand_bits,
                    }),
                    _ => Ok(Operand::RegistersAddressWordOrDword {
                        registers: AddressRegisters::from_byte(rm),
                        offset: 0,
                        bits: operand_bits,
                    })
                }
            }
            Bits::Bit32 => Err(ParseError::Unimplemented32Bit)
        }
    }

    fn read_mod1_operand_8bit_result(
        &mut self,
        rm: u8,
        address_bits: Bits
    ) -> Result<Operand, ParseError> {
        let offset = self.read_i8()?;

        match address_bits {
            Bits::Bit16 => {
                Ok(Operand::RegistersAddressByte {
                    registers: AddressRegisters::from_byte(rm),
                    offset: offset as i16,
                })
            }
            Bits::Bit32 => Err(ParseError::Unimplemented32Bit)
        }
    }

    fn read_mod1_operand_16bit_result(
        &mut self,
        rm: u8,
        operand_bits: Bits,
        address_bits: Bits,
    ) -> Result<Operand, ParseError> {
        let offset = self.read_i8()?;

        match address_bits {
            Bits::Bit16 => {
                Ok(Operand::RegistersAddressWordOrDword {
                    registers: AddressRegisters::from_byte(rm),
                    offset: offset as i16,
                    bits: operand_bits,
                })
            }
            Bits::Bit32 => Err(ParseError::Unimplemented32Bit)
        }
    }

    fn read_special_op_operand_8bit_result(
        &mut self,
        modrm: (u8, u8, u8),
        address_bits: Bits
    ) -> Result<Operand, ParseError> {
        Ok(match modrm.0 {
            0 => {
                match address_bits {
                    Bits::Bit16 => {
                        self.read_mod0_operand_8bit_result(
                            modrm.2,
                            address_bits
                        )?
                    }
                    Bits::Bit32 => return Err(ParseError::Unimplemented32Bit),
                }
            }
            1 => {
                match address_bits {
                    Bits::Bit16 => {
                        self.read_mod1_operand_8bit_result(
                            modrm.2,
                            address_bits
                        )?
                    }
                    Bits::Bit32 => return Err(ParseError::Unimplemented32Bit),
                }
            }
            3 => {
                Operand::SmallRegister { register: SmallRegister::from_byte(modrm.2) }
            }
            _ => return Err(ParseError::UnimplementedMod(modrm.0)),
        })
    }

    fn read_special_op_operand_16_or_32bit_result(
        &mut self,
        modrm: (u8, u8, u8),
        operand_bits: Bits,
        address_bits: Bits,
    ) -> Result<Operand, ParseError> {
        Ok(match modrm.0 {
            0 => {
                match address_bits {
                    Bits::Bit16 => {
                        self.read_mod0_operand_16bit_result(
                            modrm.2,
                            operand_bits,
                            address_bits,
                        )?
                    }
                    Bits::Bit32 => return Err(ParseError::Unimplemented32Bit),
                }
            }
            1 => {
                match address_bits {
                    Bits::Bit16 => {
                        self.read_mod1_operand_16bit_result(
                            modrm.2,
                            operand_bits,
                            address_bits,
                        )?
                    }
                    Bits::Bit32 => return Err(ParseError::Unimplemented32Bit),
                }
            }
            3 => {
                Operand::Register {
                    register: Register::from_byte(modrm.2, operand_bits)
                }
            }
            _ => return Err(ParseError::UnimplementedMod(modrm.0)),
        })
    }

    fn read_segregpair_general(
        &mut self,
        address_bits: Bits,
    ) -> Result<(Operand, Operand), ParseError> {
        let modrm = self.read_modrm()?;
        match modrm.0 {
            0 => {
                let first_reg = SegmentRegister::from_byte(modrm.1)?;
                // The operand bits are always Bits::Bit16 because the segment
                // registers are only 16 bits wide
                let second_operand = self.read_mod0_operand_16bit_result(modrm.2, Bits::Bit16, address_bits)?;

                Ok((
                    Operand::SegmentRegister { register: first_reg },
                    second_operand,
                ))
            }
            3 => {
                let first_reg = SegmentRegister::from_byte(modrm.1)?;
                let second_reg = Register::from_byte(modrm.2, Bits::Bit16);

                Ok((
                    Operand::SegmentRegister { register: first_reg },
                    Operand::Register { register: second_reg },
                ))
            }
            _ => Err(ParseError::UnimplementedMod(modrm.0))
        }
    }

    fn read_regpair_general(
        &mut self,
        operand_bits: Bits,
        address_bits: Bits,
    ) -> Result<(Operand, Operand), ParseError> {
        let modrm = self.read_modrm()?;
        let first_reg = Register::from_byte(modrm.1, operand_bits);

        match modrm.0 {
            0 => {
                match address_bits {
                    Bits::Bit16 => {
                        let second_mem = self.read_mod0_operand_16bit_result(
                            modrm.2,
                            operand_bits,
                            address_bits
                        )?;

                        Ok((
                            Operand::Register { register: first_reg },
                            second_mem,
                        ))
                    }
                    Bits::Bit32 => return Err(ParseError::Unimplemented32Bit),
                }
            }
            1 => {
                match address_bits {
                    Bits::Bit16 => {
                        let second_mem = self.read_mod1_operand_16bit_result(
                            modrm.2,
                            operand_bits,
                            address_bits
                        )?;

                        Ok((
                            Operand::Register { register: first_reg },
                            second_mem,
                        ))
                    }
                    Bits::Bit32 => return Err(ParseError::Unimplemented32Bit),
                }
            }
            3 => {
                let second_reg = Register::from_byte(modrm.2, operand_bits);

                Ok((
                    Operand::Register { register: first_reg },
                    Operand::Register { register: second_reg },
                ))
            }
            _ => Err(ParseError::UnimplementedMod(modrm.0))
        }
    }
}

#[inline(never)]
pub fn parse_data<'data>(
    input: &'data [u8],
    opts: Options,
    bits: Bits,
) -> (Vec<Result<Op<'data>, ParseError>>, Vec<isize>) {
    let mut stream = X86ByteStream::new(input);

    let mut resulting_ops = Vec::new();
    let mut jump_targets = Vec::new();

    while stream.pos < stream.bytes.len() {
        let data_start = stream.pos;

        if let Some(stop_after) = opts.stop_after {
            if data_start >= stop_after {
                while stream.pos < stream.bytes.len() {
                    let read_bytes = (stream.bytes.len() - stream.pos).min(16);
                    let raw_data = &stream.bytes[stream.pos..stream.pos + read_bytes];
                    let op = Op {
                        raw_data,
                        prefixes: vec![],
                        opcode: OpCode::SpecialData,
                        operands: vec![],
                    };

                    resulting_ops.push(Ok(op));

                    stream.pos += read_bytes;
                }

                break;
            }
        }

        let opcode = stream.read_u8();
        let mut prefixes = Vec::new();

        let op = opcode.and_then(|mut opcode| {
            let mut op_size_applied = false;
            let mut ad_size_applied = false;
            loop {
                match opcode {
                    0x66 => {
                        op_size_applied = true;
                        prefixes.push(OpPrefix::OpSize);
                    }
                    0x67 => {
                        ad_size_applied = true;
                        prefixes.push(OpPrefix::AdSize);
                    }
                    0xF2 => prefixes.push(OpPrefix::RepNz),
                    0xF3 => prefixes.push(OpPrefix::Rep),
                    _ => break,
                }

                opcode = stream.read_u8()?;
            }

            let operand_bits = bits.switch_if(op_size_applied);
            let address_bits = bits.switch_if(ad_size_applied);

            // http://ref.x86asm.net/coder32.html
            let op_info = match opcode {
                0x03 => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits
                    )?;

                    (OpCode::Xor, vec![operands.0, operands.1])
                }
                0x07 => {
                    (OpCode::Pop, vec![Operand::SegmentRegister {
                        register: SegmentRegister::Es
                    }])
                }
                0x08 => {
                    let modrm = stream.read_modrm()?;
                    let first_operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                    let second_operand = SmallRegister::from_byte(modrm.1);
                    let second_operand = Operand::SmallRegister {
                        register: second_operand
                    };

                    (OpCode::Or, vec![first_operand, second_operand])
                }
                0x0F => {
                    let second_byte = stream.read_u8()?;
                    match second_byte {
                        0x84 => {
                            match address_bits {
                                Bits::Bit16 => {
                                    let offset = stream.read_i16()?;

                                    jump_targets.push(stream.pos as isize + offset as isize);

                                    (OpCode::Jz, vec![Operand::RelativeOffset16 {
                                        offset
                                    }])
                                }
                                Bits::Bit32 => {
                                    let offset = stream.read_i32()?;

                                    jump_targets.push(stream.pos as isize + offset as isize);

                                    (OpCode::Jz, vec![Operand::RelativeOffset32 {
                                        offset
                                    }])
                                }
                            }
                        }
                        _ => return Err(ParseError::UnimplementedTwoByteOp(second_byte)),
                    }
                }
                0x1E => {
                    (OpCode::Push, vec![Operand::SegmentRegister {
                        register: SegmentRegister::Ds
                    }])
                }
                0x1F => {
                    (OpCode::Pop, vec![Operand::SegmentRegister {
                        register: SegmentRegister::Ds
                    }])
                }
                0x24 => {
                    let al_reg = Operand::SmallRegister {
                        register: SmallRegister::Al
                    };

                    (OpCode::And, vec![
                        al_reg,
                        Operand::Constant8 {
                            value: stream.read_u8()?
                        }
                    ])
                }
                0x25 => {
                    let ax_reg = Operand::Register {
                        register: Register::from_byte(0, operand_bits)
                    };

                    let second_operand = match operand_bits {
                        Bits::Bit16 => Operand::Constant16 {
                            value: stream.read_u16()?
                        },
                        Bits::Bit32 => Operand::Constant32 {
                            value: stream.read_u32()?
                        },
                    };

                    (OpCode::And, vec![ax_reg, second_operand])
                }
                0x2D => {
                    let ax_reg = Operand::Register {
                        register: Register::from_byte(0, operand_bits)
                    };

                    let second_operand = match operand_bits {
                        Bits::Bit16 => Operand::Constant16 {
                            value: stream.read_u16()?
                        },
                        Bits::Bit32 => Operand::Constant32 {
                            value: stream.read_u32()?
                        },
                    };

                    (OpCode::Sub, vec![ax_reg, second_operand])
                }
                0x31 => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits
                    )?;

                    (OpCode::Xor, vec![operands.1, operands.0])
                }
                0x33 => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits
                    )?;

                    (OpCode::Xor, vec![operands.0, operands.1])
                }
                0x38 => {
                    let modrm = stream.read_modrm()?;
                    let first_operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                    let second_operand = SmallRegister::from_byte(modrm.1);
                    let second_operand = Operand::SmallRegister {
                        register: second_operand
                    };

                    (OpCode::Cmp, vec![first_operand, second_operand])
                }
                0x3A => {
                    let modrm = stream.read_modrm()?;
                    let first_operand = SmallRegister::from_byte(modrm.1);
                    let first_operand = Operand::SmallRegister {
                        register: first_operand
                    };

                    let second_operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                    (OpCode::Cmp, vec![first_operand, second_operand])
                }
                0x3B => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits
                    )?;

                    (OpCode::Cmp, vec![operands.0, operands.1])
                }
                0x3C => {
                    let compared = stream.read_u8()?;

                    (OpCode::Cmp, vec![
                        Operand::SmallRegister {
                            register: SmallRegister::Al
                        },
                        Operand::Constant8 {
                            value: compared
                        }
                    ])
                }
                0x40..=0x47 => {
                    let register = Register::from_byte(opcode - 0x40, operand_bits);
                    let register = Operand::Register { register };

                    (OpCode::Inc, vec![register])
                }
                0x48..=0x4F => {
                    let register = Register::from_byte(opcode - 0x48, operand_bits);
                    let register = Operand::Register { register };

                    (OpCode::Dec, vec![register])
                }
                0x50..=0x57 => {
                    let register = Register::from_byte(opcode - 0x50, operand_bits);
                    let register = Operand::Register { register };

                    (OpCode::Push, vec![register])
                }
                0x58..=0x5F => {
                    let register = Register::from_byte(opcode - 0x58, operand_bits);
                    let register = Operand::Register { register };

                    (OpCode::Pop, vec![register])
                }
                0x60 => {
                    (OpCode::PushA, vec![])
                }
                0x61 => {
                    (OpCode::PopA, vec![])
                }
                0x69 => {
                    let operands = stream.read_regpair_general(operand_bits, address_bits)?;
                    let constant = match operand_bits {
                        Bits::Bit16 => Operand::Constant16 {
                            value: stream.read_u16()?
                        },
                        Bits::Bit32 => Operand::Constant32 {
                            value: stream.read_u32()?
                        }
                    };

                    (OpCode::Imul, vec![operands.0, operands.1, constant])
                }
                0x6C => {
                    (OpCode::InSb, vec![])
                }
                0x6E => {
                    (OpCode::OutSb, vec![])
                }
                0x6F => {
                    (OpCode::OutSw, vec![])
                }
                0x72 => {
                    let offset = stream.read_i8()?;

                    jump_targets.push(stream.pos as isize + offset as isize);

                    (OpCode::Jb, vec![Operand::RelativeOffset8 {
                        offset
                    }])
                }
                0x73 => {
                    let offset = stream.read_i8()?;

                    jump_targets.push(stream.pos as isize + offset as isize);

                    (OpCode::Jae, vec![Operand::RelativeOffset8 {
                        offset
                    }])
                }
                0x74 => {
                    let offset = stream.read_i8()?;

                    jump_targets.push(stream.pos as isize + offset as isize);

                    (OpCode::Jz, vec![Operand::RelativeOffset8 {
                        offset
                    }])
                }
                0x75 => {
                    let offset = stream.read_i8()?;

                    jump_targets.push(stream.pos as isize + offset as isize);

                    (OpCode::Jnz, vec![Operand::RelativeOffset8 {
                        offset
                    }])
                }
                0x76 => {
                    let offset = stream.read_i8()?;

                    jump_targets.push(stream.pos as isize + offset as isize);

                    (OpCode::Jbe, vec![Operand::RelativeOffset8 {
                        offset
                    }])
                }
                0x7C => {
                    let offset = stream.read_i8()?;

                    jump_targets.push(stream.pos as isize + offset as isize);

                    (OpCode::Jl, vec![Operand::RelativeOffset8 {
                        offset
                    }])
                }
                0x7D => {
                    let offset = stream.read_i8()?;

                    jump_targets.push(stream.pos as isize + offset as isize);

                    (OpCode::Jge, vec![Operand::RelativeOffset8 {
                        offset
                    }])
                }
                0x80 => {
                    let modrm = stream.read_modrm()?;
                    let instr = match modrm.1 {
                        0 => OpCode::Add,
                        1 => OpCode::Or,
                        2 => OpCode::Adc,
                        3 => OpCode::Sbb,
                        4 => OpCode::And,
                        5 => OpCode::Sub,
                        6 => OpCode::Xor,
                        7 => OpCode::Cmp,
                        _ => unreachable!(),
                    };

                    let first_operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                    (instr, vec![
                        first_operand,
                        Operand::Constant8 {
                            value: stream.read_u8()?
                        }
                    ])
                }
                0x81 => {
                    let modrm = stream.read_modrm()?;
                    let instr = match modrm.1 {
                        0 => OpCode::Add,
                        1 => OpCode::Or,
                        2 => OpCode::Adc,
                        3 => OpCode::Sbb,
                        4 => OpCode::And,
                        5 => OpCode::Sub,
                        6 => OpCode::Xor,
                        7 => OpCode::Cmp,
                        _ => unreachable!(),
                    };

                    let first_operand = stream.read_special_op_operand_16_or_32bit_result(modrm, operand_bits, address_bits)?;

                    let second_operand = match operand_bits {
                        Bits::Bit16 => Operand::Constant16 {
                            value: stream.read_u16()?
                        },
                        Bits::Bit32 => Operand::Constant32 {
                            value: stream.read_u32()?
                        }
                    };

                    (instr, vec![
                        first_operand,
                        second_operand,
                    ])
                }
                0x83 => {
                    let modrm = stream.read_modrm()?;
                    let instr = match modrm.1 {
                        0 => OpCode::Add,
                        1 => OpCode::Or,
                        2 => OpCode::Adc,
                        3 => OpCode::Sbb,
                        4 => OpCode::And,
                        5 => OpCode::Sub,
                        6 => OpCode::Xor,
                        7 => OpCode::Cmp,
                        _ => unreachable!(),
                    };

                    let first_operand = stream.read_special_op_operand_16_or_32bit_result(modrm, operand_bits, address_bits)?;

                    (instr, vec![
                        first_operand,
                        Operand::Constant8 {
                            value: stream.read_u8()?
                        }
                    ])
                }
                0x84 => {
                    let modrm = stream.read_modrm()?;
                    let first_operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                    let second_operand = SmallRegister::from_byte(modrm.1);
                    let second_operand = Operand::SmallRegister {
                        register: second_operand
                    };

                    (OpCode::Test, vec![first_operand, second_operand])
                }
                0x88 => {
                    let modrm = stream.read_modrm()?;
                    let first_operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                    let second_operand = SmallRegister::from_byte(modrm.1);
                    let second_operand = Operand::SmallRegister {
                        register: second_operand
                    };

                    (OpCode::Mov, vec![first_operand, second_operand])
                }
                0x89 => {
                    let operands = stream.read_regpair_general(operand_bits, address_bits)?;
                    (OpCode::Mov, vec![operands.1, operands.0])
                }
                0x8A => {
                    let modrm = stream.read_modrm()?;
                    let first_operand = SmallRegister::from_byte(modrm.1);
                    let first_operand = Operand::SmallRegister {
                        register: first_operand
                    };

                    let second_operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                    (OpCode::Mov, vec![first_operand, second_operand])
                }
                0x8B => {
                    let operands = stream.read_regpair_general(operand_bits, address_bits)?;
                    (OpCode::Mov, vec![operands.0, operands.1])
                }
                0x8C => {
                    let operands = stream.read_segregpair_general(address_bits)?;
                    (OpCode::Mov, vec![operands.1, operands.0])
                }
                0x8E => {
                    let operands = stream.read_segregpair_general(address_bits)?;
                    (OpCode::Mov, vec![operands.0, operands.1])
                }
                0x90 => {
                    (OpCode::Nop, vec![])
                }
                0x91..=0x97 => {
                    let ax_reg = Operand::Register {
                        register: Register::from_byte(0, operand_bits)
                    };

                    let operand = Operand::Register {
                        register: Register::from_byte(opcode - 0x90, operand_bits)
                    };

                    (OpCode::Xchg, vec![operand, ax_reg])
                }
                0x98 => {
                    (OpCode::Cbw, vec![])
                }
                0xA0 => {
                    let al_reg = Operand::SmallRegister {
                        register: SmallRegister::Al
                    };

                    let mem_offset_operand = match address_bits {
                        Bits::Bit16 => {
                            let address = stream.read_u16()?;

                            Operand::AbsoluteRegisterSegmentedByteAddress16 {
                                register: SegmentRegister::Ds,
                                address,
                            }
                        }
                        Bits::Bit32 => return Err(ParseError::Unimplemented32Bit),
                    };

                    (OpCode::Mov, vec![al_reg, mem_offset_operand])
                }
                0xA1 => {
                    let ax_reg = Operand::Register {
                        register: Register::from_byte(0, operand_bits)
                    };

                    let mem_offset_operand = match address_bits {
                        Bits::Bit16 => {
                            let address = stream.read_u16()?;

                            Operand::AbsoluteRegisterSegmentedByteAddress16 {
                                register: SegmentRegister::Ds,
                                address,
                            }
                        }
                        Bits::Bit32 => return Err(ParseError::Unimplemented32Bit),
                    };

                    (OpCode::Mov, vec![ax_reg, mem_offset_operand])
                }
                0xA4 => {
                    (OpCode::MovSb, vec![])
                }
                0xA5 => {
                    match operand_bits {
                        Bits::Bit16 => (OpCode::MovSw, vec![]),
                        Bits::Bit32 => (OpCode::MovSd, vec![]),
                    }
                }
                0xAC => {
                    (OpCode::LodSb, vec![])
                }
                0xB0..=0xB7 => {
                    let register = SmallRegister::from_byte(opcode - 0xB0);
                    let register = Operand::SmallRegister { register };

                    (OpCode::Mov, vec![
                        register,
                        Operand::Constant8 {
                            value: stream.read_u8()?
                        }
                    ])
                }
                0xB8..=0xBF => {
                    let register = Register::from_byte(opcode - 0xB8, operand_bits);
                    let register = Operand::Register { register };

                    match operand_bits {
                        Bits::Bit16 => (OpCode::Mov, vec![
                            register,
                            Operand::Constant16 {
                                value: stream.read_u16()?
                            }
                        ]),
                        Bits::Bit32 => (OpCode::Mov, vec![
                            register,
                            Operand::Constant32 {
                                value: stream.read_u32()?
                            }
                        ]),
                    }
                }
                0xC0 => {
                    let modrm = stream.read_modrm()?;
                    let instr = match modrm.1 {
                        0 => OpCode::Rol,
                        1 => OpCode::Ror,
                        2 => OpCode::Rcl,
                        3 => OpCode::Rcr,
                        4 => OpCode::Shl,
                        5 => OpCode::Shr,
                        6 => OpCode::Shl,
                        7 => OpCode::Sar,
                        _ => unreachable!(),
                    };

                    let first_operand = stream.read_special_op_operand_8bit_result(
                        modrm,
                        address_bits,
                    )?;

                    let second_operand = Operand::Constant8 {
                        value: stream.read_u8()?
                    };

                    (instr, vec![first_operand, second_operand])
                }
                0xC1 => {
                    let modrm = stream.read_modrm()?;
                    let instr = match modrm.1 {
                        0 => OpCode::Rol,
                        1 => OpCode::Ror,
                        2 => OpCode::Rcl,
                        3 => OpCode::Rcr,
                        4 => OpCode::Shl,
                        5 => OpCode::Shr,
                        6 => OpCode::Shl,
                        7 => OpCode::Sar,
                        _ => unreachable!(),
                    };

                    let first_operand = stream.read_special_op_operand_16_or_32bit_result(
                        modrm,
                        operand_bits,
                        address_bits
                    )?;

                    let second_operand = Operand::Constant8 {
                        value: stream.read_u8()?
                    };

                    (instr, vec![first_operand, second_operand])
                }
                0xC6 => {
                    let modrm = stream.read_modrm()?;
                    let operand = stream.read_special_op_operand_8bit_result(
                        modrm,
                        address_bits
                    )?;

                    (OpCode::Mov, vec![
                        operand,
                        Operand::Constant8 {
                            value: stream.read_u8()?
                        }
                    ])
                }
                0xC7 => {
                    let modrm = stream.read_modrm()?;
                    let operand = stream.read_special_op_operand_16_or_32bit_result(
                        modrm,
                        operand_bits,
                        address_bits,
                    )?;

                    let second_operand = match operand_bits {
                        Bits::Bit16 => Operand::Constant16 {
                            value: stream.read_u16()?
                        },
                        Bits::Bit32 => Operand::Constant32 {
                            value: stream.read_u32()?
                        }
                    };

                    (OpCode::Mov, vec![
                        operand,
                        second_operand,
                    ])
                }
                0xCB => {
                    (OpCode::RetF, vec![])
                }
                0xCD => {
                    (OpCode::Int, vec![Operand::Constant8 {
                        value: stream.read_u8()?
                    }])
                }
                0xD3 => {
                    let modrm = stream.read_modrm()?;
                    let instr = match modrm.1 {
                        0 => OpCode::Rol,
                        1 => OpCode::Ror,
                        2 => OpCode::Rcl,
                        3 => OpCode::Rcr,
                        4 => OpCode::Shl,
                        5 => OpCode::Shr,
                        6 => OpCode::Shl,
                        7 => OpCode::Sar,
                        _ => unreachable!(),
                    };

                    let operand = stream.read_special_op_operand_16_or_32bit_result(
                        modrm,
                        operand_bits,
                        address_bits
                    )?;

                    let cl_reg = Operand::SmallRegister {
                        register: SmallRegister::Cl
                    };

                    (instr, vec![operand, cl_reg])
                }
                0xE2 => {
                    let offset = stream.read_i8()?;

                    jump_targets.push(stream.pos as isize + offset as isize);

                    (OpCode::Loop, vec![Operand::RelativeOffset8 {
                        offset
                    }])
                }
                0xE8 => {
                    match address_bits {
                        Bits::Bit16 => {
                            let offset = stream.read_i16()?;

                            jump_targets.push(stream.pos as isize + offset as isize);

                            (OpCode::Call, vec![Operand::RelativeOffset16 {
                                offset
                            }])
                        }
                        Bits::Bit32 => {
                            let offset = stream.read_i32()?;

                            jump_targets.push(stream.pos as isize + offset as isize);

                            (OpCode::Call, vec![Operand::RelativeOffset32 {
                                offset
                            }])
                        }
                    }
                }
                0xE9 => {
                    match address_bits {
                        Bits::Bit16 => {
                            let offset = stream.read_i16()?;

                            jump_targets.push(stream.pos as isize + offset as isize);

                            (OpCode::Jmp, vec![Operand::RelativeOffset16 {
                                offset
                            }])
                        }
                        Bits::Bit32 => {
                            let offset = stream.read_i32()?;

                            jump_targets.push(stream.pos as isize + offset as isize);

                            (OpCode::Jmp, vec![Operand::RelativeOffset32 {
                                offset
                            }])
                        }
                    }
                }
                0xEA => {
                    match address_bits {
                        Bits::Bit16 => {
                            let offset = stream.read_u16()?;
                            let segment = stream.read_u16()?;

                            (
                                OpCode::Jmp,
                                vec![Operand::AbsoluteConstantSegmentedOffset16 {
                                    segment,
                                    offset,
                                }]
                            )
                        }
                        Bits::Bit32 => {
                            let offset = stream.read_u32()?;
                            let segment = stream.read_u16()?;

                            (
                                OpCode::Jmp,
                                vec![Operand::AbsoluteConstantSegmentedOffset32 {
                                    segment,
                                    offset,
                                }]
                            )
                        }
                    }
                }
                0xEB => {
                    let offset = stream.read_i8()?;

                    jump_targets.push(stream.pos as isize + offset as isize);

                    let jump_result = (OpCode::Jmp, vec![Operand::RelativeOffset8 {
                        offset
                    }]);

                    if opts.skips_first_jump && offset > 4 && data_start == 0 {
                        resulting_ops.push(Ok(Op {
                            raw_data: &stream.bytes[data_start..stream.pos],
                            prefixes: prefixes.clone(),
                            opcode: jump_result.0,
                            operands: jump_result.1.clone(),
                        }));

                        let end_pos = stream.pos + offset as usize;

                        while stream.pos < end_pos {
                            let read_bytes = (end_pos - stream.pos).min(16);
                            let raw_data = &stream.bytes[stream.pos..stream.pos + read_bytes];
                            let op = Op {
                                raw_data,
                                prefixes: vec![],
                                opcode: OpCode::SpecialData,
                                operands: vec![],
                            };

                            stream.pos += read_bytes;

                            resulting_ops.push(Ok(op));
                        }

                        (OpCode::SpecialNotOp, vec![])
                    } else {
                        jump_result
                    }
                }
                0xF6 => {
                    let modrm = stream.read_modrm()?;
                    match modrm.1 {
                        0 | 1 => {
                            let operand = stream.read_special_op_operand_8bit_result(
                                modrm,
                                address_bits
                            )?;

                            (OpCode::Test, vec![
                                operand,
                                Operand::Constant8 {
                                    value: stream.read_u8()?
                                }
                            ])
                        }
                        _ => return Err(ParseError::UnimplementedReg(modrm.1)),
                    }
                }
                0xF7 => {
                    let modrm = stream.read_modrm()?;
                    match modrm.1 {
                        4 => {
                            let operand = stream.read_special_op_operand_16_or_32bit_result(
                                modrm,
                                operand_bits,
                                address_bits,
                            )?;

                            (OpCode::Mul, vec![operand])
                        }
                        6 => {
                            let operand = stream.read_special_op_operand_16_or_32bit_result(
                                modrm,
                                operand_bits,
                                address_bits,
                            )?;

                            (OpCode::Div, vec![operand])
                        }
                        _ => return Err(ParseError::UnimplementedReg(modrm.1)),
                    }
                }
                0xFA => {
                    (OpCode::Cli, vec![])
                }
                0xFB => {
                    (OpCode::Sti, vec![])
                }
                0xFC => {
                    (OpCode::Cld, vec![])
                }
                0xFE => {
                    let modrm = stream.read_modrm()?;
                    let instr = match modrm.1 {
                        0 => OpCode::Inc,
                        1 => OpCode::Dec,
                        _ => return Err(ParseError::InvalidReg(modrm.1)),
                    };

                    let operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                    (instr, vec![operand])
                }
                0xFF => {
                    let modrm = stream.read_modrm()?;
                    match modrm.1 {
                        4 => {
                            let operand = stream.read_special_op_operand_16_or_32bit_result(
                                modrm,
                                operand_bits,
                                address_bits,
                            )?;

                            (OpCode::Jmp, vec![operand])
                        }
                        _ => return Err(ParseError::UnimplementedReg(modrm.1)),
                    }
                }
                _ => return Err(ParseError::UnimplementedOp(opcode)),
            };

            Ok(Op {
                raw_data: &stream.bytes[data_start..stream.pos],
                prefixes,
                opcode: op_info.0,
                operands: op_info.1.into(),
            })
        });

        if let Ok(Op { opcode: OpCode::SpecialNotOp, .. }) = op {
            continue;
        }

        let is_err = op.is_err();
        resulting_ops.push(op);

        if is_err {
            break;
        }
    }

    return (resulting_ops, jump_targets);
}
