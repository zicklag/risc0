// Copyright 2022 Risc0, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use log::LevelFilter;
use serde::de::{self, Deserialize, Deserializer, Visitor, SeqAccess, MapAccess};
use serde::ser::{Serialize, Serializer, SerializeStruct};
use std::{ffi::CString, fmt, mem};

mod exception;
mod ffi;

pub use exception::Exception;

pub type Result<T> = std::result::Result<T, Exception>;

pub struct Receipt {
    ptr: *const ffi::RawReceipt,
}

pub struct Prover {
    ptr: *mut ffi::RawProver,
}

fn into_words(slice: &[u8]) -> Result<Vec<u32>> {
    let mut vec = Vec::new();
    let chunks = slice.chunks_exact(4);
    assert!(chunks.remainder().len() == 0);
    for chunk in chunks {
        let word = chunk[0] as u32
            | (chunk[1] as u32) << 8
            | (chunk[2] as u32) << 16
            | (chunk[3] as u32) << 24;
        vec.push(word);
    }
    Ok(vec)
}

impl Receipt {
    pub fn from_raw(journal_raw: &[u8], seal_raw: &[u32]) -> Result<Receipt> {
        let mut err = ffi::RawError::default();
        let ptr = unsafe {
            ffi::risc0_receipt_from_raw(
                &mut err,
                journal_raw.as_ptr(),
                journal_raw.len(),
                seal_raw.as_ptr(),
                seal_raw.len(),
            )
        };
        let ptr = ffi::check(err, || ptr)?;
        Ok(Receipt { ptr })
    }

    pub fn verify(&self, elf_path: &str) -> Result<()> {
        let mut err = ffi::RawError::default();
        let str = CString::new(elf_path).unwrap();
        unsafe { ffi::risc0_receipt_verify(&mut err, str.as_ptr(), self.ptr) };
        ffi::check(err, || ())
    }

    pub fn get_seal(&self) -> Result<&[u32]> {
        unsafe {
            let mut err = ffi::RawError::default();
            let buf = ffi::risc0_receipt_get_seal_buf(&mut err, self.ptr);
            let buf = ffi::check(err, || buf)?;
            let mut err = ffi::RawError::default();
            let len = ffi::risc0_receipt_get_seal_len(&mut err, self.ptr);
            let len = ffi::check(err, || len)?;
            Ok(std::slice::from_raw_parts(buf, len))
        }
    }

    pub fn get_journal(&self) -> Result<&[u8]> {
        unsafe {
            let mut err = ffi::RawError::default();
            let buf = ffi::risc0_receipt_get_journal_buf(&mut err, self.ptr);
            let buf = ffi::check(err, || buf)?;
            let mut err = ffi::RawError::default();
            let len = ffi::risc0_receipt_get_journal_len(&mut err, self.ptr);
            let len = ffi::check(err, || len)?;
            Ok(std::slice::from_raw_parts(buf, len))
        }
    }

    pub fn get_journal_vec(&self) -> Result<Vec<u32>> {
        into_words(self.get_journal()?)
    }
}

impl Serialize for Receipt {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Receipt", 2)?;
        state.serialize_field("journal", self.get_journal().unwrap())?;
        state.serialize_field("seal", self.get_seal().unwrap())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Receipt {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field { Journal, Seal }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`journal` or `seal`")
                    }

                    fn visit_str<E>(self, value: &str) -> std::result::Result<Field, E>
                    where
                        E: de::Error,
                    {
                        match value {
                            "journal" => Ok(Field::Journal),
                            "seal" => Ok(Field::Seal),
                            _ => Err(de::Error::unknown_field(value, FIELDS)),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct ReceiptVisitor;

        impl<'de> Visitor<'de> for ReceiptVisitor {
            type Value = Receipt;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Receipt")
            }

            fn visit_seq<V>(self, mut seq: V) -> std::result::Result<Receipt, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let journal: Vec<u8> = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let seal: Vec<u32> = seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                Ok(Receipt::from_raw(&journal[..], &seal[..]).unwrap())
            }

            fn visit_map<V>(self, mut map: V) -> std::result::Result<Receipt, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut journal: Option<Vec<u8>> = None;
                let mut seal: Option<Vec<u32>> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Journal => {
                            if journal.is_some() {
                                return Err(de::Error::duplicate_field("journal"));
                            }
                            journal = Some(map.next_value()?);
                        }
                        Field::Seal => {
                            if seal.is_some() {
                                return Err(de::Error::duplicate_field("seal"));
                            }
                            seal = Some(map.next_value()?);
                        }
                    }
                }
                let journal = journal.ok_or_else(|| de::Error::missing_field("journal"))?;
                let seal = seal.ok_or_else(|| de::Error::missing_field("seal"))?;
                Ok(Receipt::from_raw(&journal[..], &seal[..]).unwrap())
            }
        }

        const FIELDS: &'static [&'static str] = &["journal", "seal"];
        deserializer.deserialize_struct("Receipt", FIELDS, ReceiptVisitor)
    }
}

impl Prover {
    pub fn new(elf_path: &str) -> Result<Self> {
        let mut err = ffi::RawError::default();
        let str = CString::new(elf_path).unwrap();
        let ptr = unsafe { ffi::risc0_prover_new(&mut err, str.as_ptr()) };
        ffi::check(err, || Prover { ptr })
    }

    pub fn add_input(&mut self, slice: &[u32]) -> Result<()> {
        let mut err = ffi::RawError::default();
        unsafe {
            ffi::risc0_prover_add_input(
                &mut err,
                self.ptr,
                slice.as_ptr().cast(),
                slice.len() * mem::size_of::<u32>(),
            )
        };
        ffi::check(err, || ())
    }

    pub fn get_output(&self) -> Result<&[u8]> {
        unsafe {
            let mut err = ffi::RawError::default();
            let buf = ffi::risc0_prover_get_output_buf(&mut err, self.ptr);
            let buf = ffi::check(err, || buf)?;
            let mut err = ffi::RawError::default();
            let len = ffi::risc0_prover_get_output_len(&mut err, self.ptr);
            let len = ffi::check(err, || len)?;
            Ok(std::slice::from_raw_parts(buf, len))
        }
    }

    pub fn get_output_vec(&self) -> Result<Vec<u32>> {
        into_words(self.get_output()?)
    }

    pub fn run(&self) -> Result<Receipt> {
        let mut err = ffi::RawError::default();
        let ptr = unsafe { ffi::risc0_prover_run(&mut err, self.ptr) };
        ffi::check(err, || Receipt { ptr })
    }
}

impl Drop for Receipt {
    fn drop(&mut self) {
        let mut err = ffi::RawError::default();
        unsafe { ffi::risc0_receipt_free(&mut err, self.ptr) };
        ffi::check(err, || ()).unwrap()
    }
}

impl Drop for Prover {
    fn drop(&mut self) {
        let mut err = ffi::RawError::default();
        unsafe { ffi::risc0_prover_free(&mut err, self.ptr) };
        ffi::check(err, || ()).unwrap()
    }
}

#[ctor::ctor]
fn init() {
    env_logger::builder().filter_level(LevelFilter::Info).init();
    unsafe { ffi::risc0_init() };
}
