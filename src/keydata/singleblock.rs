struct Header {
    format: u8,
}

impl Header {
    pub fn new(format: u8) -> Header {
        Header {
            format: format,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let data = vec!{0x01, self.format};
        
        println!("header: {}", to_hex(&data));

        data
    }
}

struct KeyDataHeader {
    version: u8,
    key_id: u32,
}

impl KeyDataHeader {
    pub fn new(key_id: u32) -> KeyDataHeader {
        KeyDataHeader{
            version: 1,
            key_id: key_id,
        }
    }

    pub fn size(&self) -> u16 {
        6
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let data = vec!{
            self.version,
            4,  // header length
            ((self.key_id >> 24) & 0xff) as u8,
            ((self.key_id >> 16) & 0xff) as u8,
            ((self.key_id >> 8) & 0xff) as u8,
            (self.key_id & 0xff) as u8,
        };
        
        println!("key data header: {}", to_hex(&data));

        data
    }
}

struct Code {
    blocks: Vec<u8>,
}

enum TLCode {
    JmpIfAccessPoint,
    RuleVerifyAndStoreOverride,
    RuleVerifyValidUntil,
    CmdAccess,
    CmdAccessDenied,
    TlsEnd,
}

impl Code {
    pub fn new() -> Code {
        Code{
            blocks: Vec::new(),
        }
    }

    pub fn add(&mut self, block: Vec<u8>) -> u16 {
        let offset = self.blocks.len() as u16;
        self.blocks.extend(block);
        return offset;
    }

    pub fn size(&self) -> u16 {
        self.blocks.len() as u16
    }

    pub fn to_bytes(&self) -> Vec<u8> {

        println!("code: {}", to_hex(&self.blocks));

        self.blocks.clone()
    }
}

struct RoomListEntry {
    access_point: u32,
    offset: u16,
}

struct RoomList {
    entries: Vec<RoomListEntry>
}

impl RoomList {
    pub fn to_bytes(&self, base_offset: u16) -> Vec<u8> {
        let mut data = vec!{};
        for entry in self.entries.iter() {
            let offset = entry.offset + base_offset;
            data.extend(vec!{
                TLCode::JmpIfAccessPoint as u8,
                ((entry.access_point >> 16) & 0xff) as u8,
                ((entry.access_point >> 8) & 0xff) as u8,
                (entry.access_point & 0xff) as u8,
                ((offset >> 8) & 0xff) as u8,
                (offset & 0xff) as u8,
            });
        }
        data.push(TLCode::CmdAccessDenied as u8);
        data.push(TLCode::TlsEnd as u8);

        println!("room list: {}", to_hex(&data));

        data
    }

    fn size(&self) -> u16 {
        (self.entries.len() * 6 + 2) as u16
    }
}

pub struct SingleBlock {
    header: Header,
    data_header: KeyDataHeader,
    valid_until: u32,
    room_list: RoomList,
    code: Code,
}

impl SingleBlock {
    pub fn new(key_id: u32) -> SingleBlock {
        SingleBlock{
            header: Header::new(0xFF),
            data_header: KeyDataHeader::new(key_id),
            valid_until: 0,
            room_list: RoomList{
                entries: vec!{},
            },
            code: Code::new(),
        }
    }

    pub fn with_valid_until(mut self, time: u32) -> SingleBlock {
        self.valid_until = time;
        self
    }

    pub fn with_overriding_access(mut self, access_points: &[u32], override_number: u32) -> SingleBlock {
        let offset = self.code.add(vec!{
            TLCode::RuleVerifyAndStoreOverride as u8,
            ((override_number >> 24) & 0xff) as u8,
            ((override_number >> 16) & 0xff) as u8,
            ((override_number >> 8) & 0xff) as u8,
            (override_number & 0xff) as u8,
            TLCode::CmdAccess as u8,
            TLCode::TlsEnd as u8
        });

        for access_point in access_points.iter() {
            self.room_list.entries.push(RoomListEntry{
                access_point: *access_point,
                offset: offset,
            });
        }

        self
    }

    pub fn with_non_overriding_access(mut self, access_points: &[u32]) -> SingleBlock {
        let offset = self.code.add(vec!{
            TLCode::CmdAccess as u8,
            TLCode::TlsEnd as u8
        });

        for access_point in access_points.iter() {
            self.room_list.entries.push(RoomListEntry{
                access_point: *access_point,
                offset: offset,
            });
        }

        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = vec!{};
        
        let mut base_offset = self.data_header.size() + self.room_list.size();
        if self.valid_until > 0 {
            base_offset += 5;
        }

        let data_size = base_offset + self.code.size() + 2;

        data.extend(self.header.to_bytes());
        data.extend(vec!{
            ((data_size >> 8) & 0xff) as u8,
            (data_size & 0xff) as u8
        });

        // "encrypted" data
        data.extend(self.data_header.to_bytes());
        if self.valid_until > 0 {
            data.extend(vec!{
                TLCode::RuleVerifyValidUntil as u8,
                ((self.valid_until >> 24) & 0xff) as u8,
                ((self.valid_until >> 16) & 0xff) as u8,
                ((self.valid_until >> 8) & 0xff) as u8,
                (self.valid_until & 0xff) as u8,
            });
        }
        
        data.extend(self.room_list.to_bytes(base_offset));
        data.extend(self.code.to_bytes());

        // CRC16
        data.push(0x00);
        data.push(0x00);

        data
    }

    pub fn to_hex(&self) -> String {
        to_hex(&self.to_bytes())
    }
}


fn to_hex(data: &[u8]) -> String {
    let hex_bytes: Vec<String> = data.iter()
        .map(|b| format!("{:02X}", b))
        .collect();
    
    hex_bytes
        .join(" ")
}