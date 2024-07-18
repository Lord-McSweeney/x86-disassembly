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
                    _ => Ok(Operand::RegistersAddressByteNoOffset {
                        registers: AddressRegisters::from_byte(rm)
                    })
                }
            }
            Bits::Bit32 => Err(ParseError::Unimplemented32Bit)
        }
    }

    fn read_mod0_operand_16bit_result(
        &mut self,
        rm: u8,
        address_bits: Bits
    ) -> Result<Operand, ParseError> {
        match address_bits {
            Bits::Bit16 => {
                match rm {
                    6 => Ok(Operand::AbsoluteRegisterSegmentedWordAddress16 {
                        register: SegmentRegister::Ds,
                        address: self.read_u16()?,
                    }),
                    _ => Ok(Operand::RegistersAddressWordNoOffset {
                        registers: AddressRegisters::from_byte(rm)
                    })
                }
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
            3 => {
                Operand::SmallRegister { register: SmallRegister::from_byte(modrm.2) }
            }
            _ => return Err(ParseError::UnimplementedMod(modrm.0)),
        })
    }

    fn read_segregpair_general(
        &mut self
    ) -> Result<(Operand, Operand), ParseError> {
        let modrm = self.read_modrm()?;
        match modrm.0 {
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
                        let second_mem = self.read_mod0_operand_16bit_result(modrm.2, address_bits)?;

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
    bits: Bits
) -> (Vec<Result<Op<'data>, ParseError>>, Vec<isize>) {
    let mut stream = X86ByteStream::new(input);

    let mut resulting_ops = Vec::new();
    let mut jump_targets = Vec::new();

    while stream.pos < stream.bytes.len() {
        let data_start = stream.pos;

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

            let op_info = match opcode {
                0x07 => {
                    (OpCode::Pop, vec![Operand::SegmentRegister {
                        register: SegmentRegister::Es
                    }])
                }
                0x1F => {
                    (OpCode::Pop, vec![Operand::SegmentRegister {
                        register: SegmentRegister::Ds
                    }])
                }
                0x33 => {
                    let operands = stream.read_regpair_general(operand_bits, address_bits)?;
                    (OpCode::Xor, vec![operands.0, operands.1])
                }
                0x50..=0x57 => {
                    let register = Register::from_byte(opcode - 0x50, operand_bits);
                    let register = Operand::Register { register };

                    (OpCode::Push, vec![register])
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

                    // TODO: Extract this out into a function?
                    let first_operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                    (instr, vec![
                        first_operand,
                        Operand::Constant8 {
                            value: stream.read_u8()?
                        }
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

                    // TODO: Extract this out into a function?
                    let first_operand = match modrm.0 {
                        3 => {
                            Operand::Register {
                                register: Register::from_byte(modrm.2, operand_bits)
                            }
                        }
                        _ => return Err(ParseError::UnimplementedMod(modrm.0)),
                    };

                    (instr, vec![
                        first_operand,
                        Operand::Constant8 {
                            value: stream.read_u8()?
                        }
                    ])
                }
                0x8B => {
                    let operands = stream.read_regpair_general(operand_bits, address_bits)?;
                    (OpCode::Mov, vec![operands.0, operands.1])
                }
                0x8E => {
                    let operands = stream.read_segregpair_general()?;
                    (OpCode::Mov, vec![operands.0, operands.1])
                }
                0x90 => {
                    (OpCode::Nop, vec![])
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
                0xCB => {
                    (OpCode::RetF, vec![])
                }
                0xCD => {
                    (OpCode::Int, vec![Operand::Constant8 {
                        value: stream.read_u8()?
                    }])
                }
                0xEA => {
                    match address_bits {
                        Bits::Bit16 => {
                            let offset = stream.read_u16()?;
                            let segment = stream.read_u16()?;

                            (
                                OpCode::Jump,
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
                                OpCode::Jump,
                                vec![Operand::AbsoluteConstantSegmentedOffset32 {
                                    segment,
                                    offset,
                                }]
                            )
                        }
                    }
                }
                0xE9 => {
                    match address_bits {
                        Bits::Bit16 => {
                            let offset = stream.read_i16()?;

                            jump_targets.push(stream.pos as isize + offset as isize);

                            (OpCode::Jump, vec![Operand::RelativeOffset16 {
                                offset
                            }])
                        }
                        Bits::Bit32 => {
                            let offset = stream.read_i32()?;

                            jump_targets.push(stream.pos as isize + offset as isize);

                            (OpCode::Jump, vec![Operand::RelativeOffset32 {
                                offset
                            }])
                        }
                    }
                }
                0xEB => {
                    let offset = stream.read_i8()?;

                    jump_targets.push(stream.pos as isize + offset as isize);

                    (OpCode::Jump, vec![Operand::RelativeOffset8 {
                        offset
                    }])
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
                _ => return Err(ParseError::UnimplementedOp(opcode)),
            };
            
            Ok(Op {
                raw_data: &stream.bytes[data_start..stream.pos],
                prefixes,
                opcode: op_info.0,
                operands: op_info.1.into(),
            })
        });

        let is_err = op.is_err();
        resulting_ops.push(op);

        if is_err {
            break;
        }
    }

    return (resulting_ops, jump_targets);
}
