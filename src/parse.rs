/*
- https://wiki.osdev.org/X86-64_Instruction_Encoding#16-bit_addressing
In 16bit mode the ModR/M byte is very simple. It includes a
2bit mod:
    00 for addressing
    01 for addressing with 8-bit offset
    10 for addressing with 16-bit offset
    11 for registers

3bit reg:
    Always a register.
    000 for AX
    001 for CX
    010 for DX
    011 for BX
    100 for SP
    101 for BP
    110 for SI
    111 for DI

3bit rm
    If mod is set to 11, this specifies a register.
        000 for AX
        001 for CX
        010 for DX
        011 for BX
        100 for SP
        101 for BP
        110 for SI
        111 for DI
    Otherwise, it specifies a group of addressing registers.
        000 for BX+SI
        001 for BX+DI
        010 for BP+SI
        011 for BP+DI
        100 for SI
        101 for DI
        110 for BP (SEE BELOW NOTE)
        111 for BX

    NOTE: When mod is set to 00, rm 110 instead specifies something else:
        that the op is a memory access from [ADDRESS], where ADDRESS is
        a 16-bit absolute address (though it's by-default offset by DS)
        that comes in the two bytes following the ModR/M byte.


- https://wiki.osdev.org/X86-64_Instruction_Encoding#32/64-bit_addressing
    (the 3 bits for R/M is 3 bits in x32 mode, ignore the 4 bits present
    on the page- it's for using REX prefixes in x64 mode)

In 32bit mode the ModR/M byte is more complicated,
and an extra SIB (scale, index, base) byte is sometimes present. The osdev
page covers the SIB byte, but here's another page for a little more detail:
http://www.c-jump.com/CIS77/CPU/x86/X77_0110_scaled_indexed.htm
*/

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

    fn read_16_or_32bit_constant(
        &mut self,
        bits: Bits
    ) -> Result<Operand, ParseError> {
        Ok(match bits {
            Bits::Bit16 => Operand::Constant16 {
                value: self.read_u16()?
            },
            Bits::Bit32 => Operand::Constant32 {
                value: self.read_u32()?
            }
        })
    }

    // See https://wiki.osdev.org/X86-64_Instruction_Encoding#16-bit_addressing
    fn read_modrm(&mut self) -> Result<(u8, u8, u8), ParseError> {
        let byte = self.read_u8()?;

        let mod_part = byte >> 6;
        let reg_part = (byte >> 3) & 0x7;
        let r_m_part = byte & 0x7;

        Ok((mod_part, reg_part, r_m_part))
    }

    fn read_16bit_mod0_operand_8bit_result(
        &mut self,
        rm: u8
    ) -> Result<Operand, ParseError> {
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

    fn read_16bit_mod0_operand_16bit_result(
        &mut self,
        rm: u8,
        operand_bits: Bits,
    ) -> Result<Operand, ParseError> {
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

    fn read_16bit_mod1_operand_8bit_result(
        &mut self,
        rm: u8
    ) -> Result<Operand, ParseError> {
        let offset = self.read_i8()?;

        Ok(Operand::RegistersAddressByte {
            registers: AddressRegisters::from_byte(rm),
            offset: offset as i16,
        })
    }

    fn read_16bit_mod1_operand_16bit_result(
        &mut self,
        rm: u8,
        operand_bits: Bits,
    ) -> Result<Operand, ParseError> {
        let offset = self.read_i8()?;

        Ok(Operand::RegistersAddressWordOrDword {
            registers: AddressRegisters::from_byte(rm),
            offset: offset as i16,
            bits: operand_bits,
        })
    }

    fn read_16bit_mod2_operand_8bit_result(
        &mut self,
        rm: u8
    ) -> Result<Operand, ParseError> {
        let offset = self.read_i16()?;

        Ok(Operand::RegistersAddressByte {
            registers: AddressRegisters::from_byte(rm),
            offset,
        })
    }

    fn read_16bit_mod2_operand_16bit_result(
        &mut self,
        rm: u8,
        operand_bits: Bits,
    ) -> Result<Operand, ParseError> {
        let offset = self.read_i16()?;

        Ok(Operand::RegistersAddressWordOrDword {
            registers: AddressRegisters::from_byte(rm),
            offset,
            bits: operand_bits,
        })
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
                        self.read_16bit_mod0_operand_8bit_result(modrm.2)?
                    }
                    Bits::Bit32 => return Err(ParseError::Unimplemented32Bit),
                }
            }
            1 => {
                match address_bits {
                    Bits::Bit16 => {
                        self.read_16bit_mod1_operand_8bit_result(modrm.2)?
                    }
                    Bits::Bit32 => return Err(ParseError::Unimplemented32Bit),
                }
            }
            2 => {
                match address_bits {
                    Bits::Bit16 => {
                        self.read_16bit_mod2_operand_8bit_result(modrm.2)?
                    }
                    Bits::Bit32 => return Err(ParseError::Unimplemented32Bit),
                }
            }
            3 => {
                Operand::SmallRegister { register: SmallRegister::from_byte(modrm.2) }
            }
            _ => unreachable!(),
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
                        self.read_16bit_mod0_operand_16bit_result(
                            modrm.2,
                            operand_bits,
                        )?
                    }
                    Bits::Bit32 => return Err(ParseError::Unimplemented32Bit),
                }
            }
            1 => {
                match address_bits {
                    Bits::Bit16 => {
                        self.read_16bit_mod1_operand_16bit_result(
                            modrm.2,
                            operand_bits,
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
                let second_operand = match address_bits {
                    Bits::Bit16 => {
                        self.read_16bit_mod0_operand_16bit_result(modrm.2, Bits::Bit16)?
                    }
                    Bits::Bit32 => return Err(ParseError::Unimplemented32Bit),
                };

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
        must_have_mem: bool,
    ) -> Result<(Operand, Operand), ParseError> {
        let modrm = self.read_modrm()?;
        let first_reg = Register::from_byte(modrm.1, operand_bits);

        match modrm.0 {
            0 => {
                match address_bits {
                    Bits::Bit16 => {
                        let second_mem = self.read_16bit_mod0_operand_16bit_result(
                            modrm.2,
                            operand_bits
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
                        let second_mem = self.read_16bit_mod1_operand_16bit_result(
                            modrm.2,
                            operand_bits
                        )?;

                        Ok((
                            Operand::Register { register: first_reg },
                            second_mem,
                        ))
                    }
                    Bits::Bit32 => return Err(ParseError::Unimplemented32Bit),
                }
            }
            2 => {
                match address_bits {
                    Bits::Bit16 => {
                        let second_mem = self.read_16bit_mod2_operand_16bit_result(
                            modrm.2,
                            operand_bits
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
                if must_have_mem {
                    Err(ParseError::InvalidLeaMod)
                } else {
                    let second_reg = Register::from_byte(modrm.2, operand_bits);

                    Ok((
                        Operand::Register { register: first_reg },
                        Operand::Register { register: second_reg },
                    ))
                }
            }
            _ => unreachable!(),
        }
    }
}

#[inline(never)]
pub fn parse_data<'data>(
    input: &'data [u8],
    opts: Options,
) -> (Vec<Result<Op<'data>, ParseError>>, Vec<isize>) {
    let bits = opts.bits;
    let mut stream = X86ByteStream::new(input);

    let mut resulting_ops = Vec::new();
    let mut jump_targets = Vec::new();

    let start_pos = opts.start_at;

    while stream.pos < start_pos {
        let read_bytes = (start_pos - stream.pos).min(16);
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
                    0x26 => prefixes.push(OpPrefix::Es),
                    0x2E => prefixes.push(OpPrefix::Cs),
                    0x64 => prefixes.push(OpPrefix::Fs),
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
                0x00 => {
                    let modrm = stream.read_modrm()?;
                    let first_operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                    let second_operand = SmallRegister::from_byte(modrm.1);
                    let second_operand = Operand::SmallRegister {
                        register: second_operand
                    };

                    (OpCode::Add, vec![first_operand, second_operand])
                }
                0x01 => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits,
                        false,
                    )?;

                    (OpCode::Add, vec![operands.1, operands.0])
                }
                0x02 => {
                    let modrm = stream.read_modrm()?;
                    let first_operand = SmallRegister::from_byte(modrm.1);
                    let first_operand = Operand::SmallRegister {
                        register: first_operand
                    };

                    let second_operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                    (OpCode::Add, vec![first_operand, second_operand])
                }
                0x03 => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits,
                        false,
                    )?;

                    (OpCode::Add, vec![operands.0, operands.1])
                }
                0x04 => {
                    (OpCode::Add, vec![
                        Operand::SmallRegister {
                            register: SmallRegister::Al
                        },
                        Operand::Constant8 {
                            value: stream.read_u8()?
                        }
                    ])
                }
                0x05 => {
                    let ax_reg = Operand::Register {
                        register: Register::from_byte(0, operand_bits)
                    };

                    let second_operand = stream.read_16_or_32bit_constant(operand_bits)?;

                    (OpCode::Add, vec![
                        ax_reg,
                        second_operand,
                    ])
                }
                0x06 => {
                    (OpCode::Push, vec![Operand::SegmentRegister {
                        register: SegmentRegister::Es
                    }])
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
                0x09 => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits,
                        false,
                    )?;

                    (OpCode::Or, vec![operands.1, operands.0])
                }
                0x0A => {
                    let modrm = stream.read_modrm()?;
                    let first_operand = SmallRegister::from_byte(modrm.1);
                    let first_operand = Operand::SmallRegister {
                        register: first_operand
                    };

                    let second_operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                    (OpCode::Or, vec![first_operand, second_operand])
                }
                0x0B => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits,
                        false,
                    )?;

                    (OpCode::Or, vec![operands.0, operands.1])
                }
                0x0C => {
                    (OpCode::Or, vec![
                        Operand::SmallRegister {
                            register: SmallRegister::Al
                        },
                        Operand::Constant8 {
                            value: stream.read_u8()?
                        }
                    ])
                }
                0x0E => {
                    (OpCode::Push, vec![Operand::SegmentRegister {
                        register: SegmentRegister::Cs
                    }])
                }
                0x0F => {
                    let second_byte = stream.read_u8()?;
                    match second_byte {
                        0x83..=0x84 => {
                            let instr = match second_byte {
                                0x83 => OpCode::Jae,
                                0x84 => OpCode::Jz,
                                _ => unreachable!(),
                            };

                            match address_bits {
                                Bits::Bit16 => {
                                    let offset = stream.read_i16()?;

                                    jump_targets.push(stream.pos as isize + offset as isize);

                                    (instr, vec![Operand::RelativeOffset16 {
                                        offset
                                    }])
                                }
                                Bits::Bit32 => {
                                    let offset = stream.read_i32()?;

                                    jump_targets.push(stream.pos as isize + offset as isize);

                                    (instr, vec![Operand::RelativeOffset32 {
                                        offset
                                    }])
                                }
                            }
                        }
                        0xB6 => {
                            let modrm = stream.read_modrm()?;

                            let first_operand = Operand::Register {
                                register: Register::from_byte(modrm.1, operand_bits),
                            };

                            let second_operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                            (OpCode::Movzx, vec![first_operand, second_operand])
                        }
                        _ => return Err(ParseError::UnimplementedTwoByteOp(second_byte)),
                    }
                }
                0x13 => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits,
                        false,
                    )?;

                    (OpCode::Adc, vec![operands.0, operands.1])
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
                    (OpCode::And, vec![
                        Operand::SmallRegister {
                            register: SmallRegister::Al
                        },
                        Operand::Constant8 {
                            value: stream.read_u8()?
                        }
                    ])
                }
                0x25 => {
                    let ax_reg = Operand::Register {
                        register: Register::from_byte(0, operand_bits)
                    };

                    let second_operand = stream.read_16_or_32bit_constant(operand_bits)?;

                    (OpCode::And, vec![ax_reg, second_operand])
                }
                0x2B => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits,
                        false,
                    )?;

                    (OpCode::Sub, vec![operands.0, operands.1])
                }
                0x2C => {
                    (OpCode::Sub, vec![
                        Operand::SmallRegister {
                            register: SmallRegister::Al
                        },
                        Operand::Constant8 {
                            value: stream.read_u8()?
                        }
                    ])
                }
                0x2D => {
                    let ax_reg = Operand::Register {
                        register: Register::from_byte(0, operand_bits)
                    };

                    let second_operand = stream.read_16_or_32bit_constant(operand_bits)?;

                    (OpCode::Sub, vec![ax_reg, second_operand])
                }
                0x30 => {
                    let modrm = stream.read_modrm()?;
                    let first_operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                    let second_operand = SmallRegister::from_byte(modrm.1);
                    let second_operand = Operand::SmallRegister {
                        register: second_operand
                    };

                    (OpCode::Xor, vec![first_operand, second_operand])
                }
                0x31 => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits,
                        false,
                    )?;

                    (OpCode::Xor, vec![operands.1, operands.0])
                }
                0x32 => {
                    let modrm = stream.read_modrm()?;
                    let first_operand = SmallRegister::from_byte(modrm.1);
                    let first_operand = Operand::SmallRegister {
                        register: first_operand
                    };

                    let second_operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                    (OpCode::Xor, vec![first_operand, second_operand])
                }
                0x33 => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits,
                        false,
                    )?;

                    (OpCode::Xor, vec![operands.0, operands.1])
                }
                0x34 => {
                    (OpCode::Xor, vec![
                        Operand::SmallRegister {
                            register: SmallRegister::Al
                        },
                        Operand::Constant8 {
                            value: stream.read_u8()?
                        }
                    ])
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
                0x39 => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits,
                        false,
                    )?;

                    (OpCode::Cmp, vec![operands.1, operands.0])
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
                        address_bits,
                        false,
                    )?;

                    (OpCode::Cmp, vec![operands.0, operands.1])
                }
                0x3C => {
                    (OpCode::Cmp, vec![
                        Operand::SmallRegister {
                            register: SmallRegister::Al
                        },
                        Operand::Constant8 {
                            value: stream.read_u8()?
                        }
                    ])
                }
                0x3D => {
                    let ax_reg = Operand::Register {
                        register: Register::from_byte(0, operand_bits)
                    };

                    let second_operand = stream.read_16_or_32bit_constant(operand_bits)?;

                    (OpCode::Cmp, vec![
                        ax_reg,
                        second_operand,
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
                0x68 => {
                    let constant = stream.read_16_or_32bit_constant(operand_bits)?;

                    (OpCode::Push, vec![constant])
                }
                0x69 => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits,
                        false,
                    )?;
                    let constant = stream.read_16_or_32bit_constant(operand_bits)?;

                    (OpCode::Imul, vec![operands.0, operands.1, constant])
                }
                0x6A => {
                    (OpCode::Push, vec![Operand::Constant8 {
                        value: stream.read_u8()?
                    }])
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
                0x77 => {
                    let offset = stream.read_i8()?;

                    jump_targets.push(stream.pos as isize + offset as isize);

                    (OpCode::Ja, vec![Operand::RelativeOffset8 {
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
                0x7F => {
                    let offset = stream.read_i8()?;

                    jump_targets.push(stream.pos as isize + offset as isize);

                    (OpCode::Jg, vec![Operand::RelativeOffset8 {
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

                    let second_operand = stream.read_16_or_32bit_constant(operand_bits)?;

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
                0x85 => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits,
                        false,
                    )?;

                    (OpCode::Test, vec![operands.1, operands.0])
                }
                0x86 => {
                    let modrm = stream.read_modrm()?;
                    let first_operand = stream.read_special_op_operand_8bit_result(modrm, address_bits)?;

                    let second_operand = SmallRegister::from_byte(modrm.1);
                    let second_operand = Operand::SmallRegister {
                        register: second_operand
                    };

                    // Order doesn't matter
                    (OpCode::Xchg, vec![first_operand, second_operand])
                }
                0x87 => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits,
                        false,
                    )?;

                    // Order doesn't matter
                    (OpCode::Xchg, vec![operands.0, operands.1])
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
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits,
                        false,
                    )?;
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
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits,
                        false,
                    )?;
                    (OpCode::Mov, vec![operands.0, operands.1])
                }
                0x8C => {
                    let operands = stream.read_segregpair_general(address_bits)?;
                    (OpCode::Mov, vec![operands.1, operands.0])
                }
                0x8D => {
                    let operands = stream.read_regpair_general(
                        operand_bits,
                        address_bits,
                        true,
                    )?;
                    (OpCode::Lea, vec![operands.0, operands.1])
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

                    // Order doesn't matter
                    (OpCode::Xchg, vec![operand, ax_reg])
                }
                0x98 => {
                    match operand_bits {
                        Bits::Bit16 => (OpCode::Cbw, vec![]),
                        Bits::Bit32 => (OpCode::CwdE, vec![]),
                    }
                }
                0x99 => {
                    match operand_bits {
                        Bits::Bit16 => (OpCode::Cwd, vec![]),
                        Bits::Bit32 => (OpCode::Cdq, vec![]),
                    }
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
                0xA2 => {
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

                    (OpCode::Mov, vec![mem_offset_operand, al_reg])
                }
                0xA3 => {
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

                    (OpCode::Mov, vec![mem_offset_operand, ax_reg])
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
                0xA6 => {
                    (OpCode::CmpSb, vec![])
                }
                0xAC => {
                    (OpCode::LodSb, vec![])
                }
                0xAD => {
                    (OpCode::LodSw, vec![])
                }
                0xAE => {
                    (OpCode::ScaSb, vec![])
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
                0xC2 => {
                    let constant = stream.read_16_or_32bit_constant(operand_bits)?;
                    (OpCode::RetN, vec![constant])
                }
                0xC3 => {
                    (OpCode::RetN, vec![])
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

                    let second_operand = stream.read_16_or_32bit_constant(operand_bits)?;

                    (OpCode::Mov, vec![
                        operand,
                        second_operand,
                    ])
                }
                0xCB => {
                    (OpCode::RetF, vec![])
                }
                0xCC => {
                    (OpCode::Int, vec![Operand::Constant8 {
                        value: 3
                    }])
                }
                0xCD => {
                    (OpCode::Int, vec![Operand::Constant8 {
                        value: stream.read_u8()?
                    }])
                }
                0xD1 => {
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

                    let constant_1 = Operand::Constant8 {
                        value: 1
                    };

                    (instr, vec![operand, constant_1])
                }
                0xD2 => {
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

                    let operand = stream.read_special_op_operand_8bit_result(
                        modrm,
                        address_bits
                    )?;

                    let cl_reg = Operand::SmallRegister {
                        register: SmallRegister::Cl
                    };

                    (instr, vec![operand, cl_reg])
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
                0xE0 => {
                    let offset = stream.read_i8()?;

                    jump_targets.push(stream.pos as isize + offset as isize);

                    (OpCode::LoopNz, vec![Operand::RelativeOffset8 {
                        offset
                    }])
                }
                0xE2 => {
                    let offset = stream.read_i8()?;

                    jump_targets.push(stream.pos as isize + offset as isize);

                    (OpCode::Loop, vec![Operand::RelativeOffset8 {
                        offset
                    }])
                }
                0xE3 => {
                    let offset = stream.read_i8()?;

                    jump_targets.push(stream.pos as isize + offset as isize);

                    (OpCode::Jcxz, vec![Operand::RelativeOffset8 {
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
                0xF8 => {
                    (OpCode::Clc, vec![])
                }
                0xF9 => {
                    (OpCode::Stc, vec![])
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
                0xFD => {
                    (OpCode::Std, vec![])
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
                        2 => {
                            let operand = stream.read_special_op_operand_16_or_32bit_result(
                                modrm,
                                operand_bits,
                                address_bits,
                            )?;

                            (OpCode::Call, vec![operand])
                        }
                        4 => {
                            let operand = stream.read_special_op_operand_16_or_32bit_result(
                                modrm,
                                operand_bits,
                                address_bits,
                            )?;

                            (OpCode::Jmp, vec![operand])
                        }
                        6 => {
                            let operand = stream.read_special_op_operand_16_or_32bit_result(
                                modrm,
                                operand_bits,
                                address_bits,
                            )?;

                            (OpCode::Push, vec![operand])
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
