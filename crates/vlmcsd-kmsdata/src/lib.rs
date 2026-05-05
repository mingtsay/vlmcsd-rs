use vlmcsd_types::Guid;

const KMD_DATA: &[u8] = include_bytes!("../../../data/vlmcsd.kmd");

const MAGIC: &[u8; 4] = b"KMD\x00";

#[derive(Debug, Clone)]
pub struct KmsData {
    pub header: KmsHeader,
    pub csvlk_data: Vec<CsvlkData>,
    pub app_items: Vec<VlmcsdItem>,
    pub kms_items: Vec<VlmcsdItem>,
    pub sku_items: Vec<VlmcsdItem>,
    pub host_builds: Vec<HostBuild>,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct KmsHeader {
    pub version_minor: u16,
    pub version_major: u16,
    pub csvlk_count: u8,
    pub flags: u8,
    pub app_item_count: i32,
    pub kms_item_count: i32,
    pub sku_item_count: i32,
    pub host_build_count: i32,
}

#[derive(Debug, Clone)]
pub struct CsvlkData {
    pub epid_offset: u64,
    pub release_date: i64,
    pub group_id: u32,
    pub min_key_id: u32,
    pub max_key_id: u32,
    pub min_active_clients: u8,
}

#[derive(Debug, Clone)]
pub struct VlmcsdItem {
    pub guid: Guid,
    pub name_offset: u64,
    pub app_index: u8,
    pub kms_index: u8,
    pub protocol_version: u8,
    pub n_count_policy: u8,
    pub is_retail: u8,
    pub is_preview: u8,
    pub epid_index: u8,
}

#[derive(Debug, Clone)]
pub struct HostBuild {
    pub display_name_offset: u64,
    pub release_date: i64,
    pub build_number: i32,
    pub platform_id: i32,
    pub flags: u32,
}

impl KmsData {
    pub fn load_embedded() -> Self {
        Self::parse(KMD_DATA).expect("embedded KMD data is invalid")
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 || &data[0..4] != MAGIC {
            return None;
        }

        let version_minor = u16::from_le_bytes([data[4], data[5]]);
        let version_major = u16::from_le_bytes([data[6], data[7]]);
        let csvlk_count = data[8];
        let flags = data[9];

        let app_item_count = i32::from_le_bytes(data[12..16].try_into().unwrap());
        let kms_item_count = i32::from_le_bytes(data[16..20].try_into().unwrap());
        let sku_item_count = i32::from_le_bytes(data[20..24].try_into().unwrap());
        let host_build_count = i32::from_le_bytes(data[24..28].try_into().unwrap());

        let app_item_offset = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
        let kms_item_offset = u64::from_le_bytes(data[40..48].try_into().unwrap()) as usize;
        let sku_item_offset = u64::from_le_bytes(data[48..56].try_into().unwrap()) as usize;
        let host_build_offset = u64::from_le_bytes(data[56..64].try_into().unwrap()) as usize;

        // CsvlkData starts at offset 72 (after the 5 DataPointers)
        // Actually, looking at the struct: 4 magic + 4 version + 1 csvlk_count + 1 flags + 2 reserved + 5*4 counts + 5*8 datapointers = 72
        // Then CsvlkData array follows
        let csvlk_start = 32 + 5 * 8; // = 72
        let csvlk_item_size = 32; // EPidOffset(8) + ReleaseDate(8) + GroupId(4) + MinKeyId(4) + MaxKeyId(4) + MinActiveClients(1) + Reserved(3) = 32

        let mut csvlk_data = Vec::with_capacity(csvlk_count as usize);
        for i in 0..csvlk_count as usize {
            let off = csvlk_start + i * csvlk_item_size;
            if off + csvlk_item_size > data.len() {
                return None;
            }
            csvlk_data.push(CsvlkData {
                epid_offset: u64::from_le_bytes(data[off..off + 8].try_into().unwrap()),
                release_date: i64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap()),
                group_id: u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap()),
                min_key_id: u32::from_le_bytes(data[off + 20..off + 24].try_into().unwrap()),
                max_key_id: u32::from_le_bytes(data[off + 24..off + 28].try_into().unwrap()),
                min_active_clients: data[off + 28],
            });
        }

        // GUID(16) + NameOffset(8) + AppIndex(1) + KmsIndex(1) + ProtocolVersion(1) + NCountPolicy(1) + IsRetail(1) + IsPreview(1) + EPidIndex(1) + reserved(1) = 32
        let vlmcsd_item_total_size = 32;

        let app_items = parse_vlmcsd_items(data, app_item_offset, app_item_count as usize, vlmcsd_item_total_size)?;
        let kms_items = parse_vlmcsd_items(data, kms_item_offset, kms_item_count as usize, vlmcsd_item_total_size)?;
        let sku_items = parse_vlmcsd_items(data, sku_item_offset, sku_item_count as usize, vlmcsd_item_total_size)?;

        let host_build_item_size = 32; // DisplayNameOffset(8) + ReleaseDate(8) + BuildNumber(4) + PlatformId(4) + Flags(4) + reserved(4)
        let mut host_builds = Vec::with_capacity(host_build_count as usize);
        for i in 0..host_build_count as usize {
            let off = host_build_offset + i * host_build_item_size;
            if off + host_build_item_size > data.len() {
                return None;
            }
            host_builds.push(HostBuild {
                display_name_offset: u64::from_le_bytes(data[off..off + 8].try_into().unwrap()),
                release_date: i64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap()),
                build_number: i32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap()),
                platform_id: i32::from_le_bytes(data[off + 20..off + 24].try_into().unwrap()),
                flags: u32::from_le_bytes(data[off + 24..off + 28].try_into().unwrap()),
            });
        }

        let header = KmsHeader {
            version_minor,
            version_major,
            csvlk_count,
            flags,
            app_item_count,
            kms_item_count,
            sku_item_count,
            host_build_count,
        };

        Some(KmsData {
            header,
            csvlk_data,
            app_items,
            kms_items,
            sku_items,
            host_builds,
            data: data.to_vec(),
        })
    }

    pub fn get_string(&self, offset: u64) -> &str {
        let off = offset as usize;
        if off >= self.data.len() {
            return "";
        }
        let end = self.data[off..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| off + p)
            .unwrap_or(self.data.len());
        std::str::from_utf8(&self.data[off..end]).unwrap_or("")
    }

    pub fn get_epid(&self, index: usize) -> &str {
        if index < self.csvlk_data.len() {
            self.get_string(self.csvlk_data[index].epid_offset)
        } else {
            ""
        }
    }

    pub fn find_kms_item(&self, guid: &Guid) -> Option<&VlmcsdItem> {
        self.kms_items.iter().rev().find(|item| item.guid == *guid)
    }

    pub fn find_app_item(&self, guid: &Guid) -> Option<&VlmcsdItem> {
        self.app_items.iter().rev().find(|item| item.guid == *guid)
    }

    pub fn find_sku_item(&self, guid: &Guid) -> Option<&VlmcsdItem> {
        self.sku_items.iter().rev().find(|item| item.guid == *guid)
    }

    pub fn find_product(&self, guid: &Guid) -> Option<(&VlmcsdItem, &str)> {
        let all_items = self.app_items.iter()
            .chain(self.kms_items.iter())
            .chain(self.sku_items.iter());
        for item in all_items.rev() {
            if item.guid == *guid {
                let name = self.get_string(item.name_offset);
                return Some((item, name));
            }
        }
        None
    }

    pub fn get_platform_id(&self, host_build: i32) -> i32 {
        for hb in &self.host_builds {
            if hb.build_number <= host_build {
                return hb.platform_id;
            }
        }
        self.host_builds.last().map(|h| h.platform_id).unwrap_or(0)
    }

    pub fn get_release_date(&self, host_build: i32) -> i64 {
        for hb in self.host_builds.iter().rev() {
            if hb.build_number >= host_build {
                return hb.release_date;
            }
        }
        self.host_builds.first().map(|h| h.release_date).unwrap_or(0)
    }
}

fn parse_vlmcsd_items(data: &[u8], offset: usize, count: usize, item_size: usize) -> Option<Vec<VlmcsdItem>> {
    let mut items = Vec::with_capacity(count);
    for i in 0..count {
        let off = offset + i * item_size;
        if off + item_size > data.len() {
            return None;
        }
        let guid = Guid::from_le_bytes(data[off..off + 16].try_into().unwrap());
        let name_offset = u64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap());
        items.push(VlmcsdItem {
            guid,
            name_offset,
            app_index: data[off + 24],
            kms_index: data[off + 25],
            protocol_version: data[off + 26],
            n_count_policy: data[off + 27],
            is_retail: data[off + 28],
            is_preview: data[off + 29],
            epid_index: data[off + 30],
        });
    }
    Some(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_embedded_kmd() {
        let kms = KmsData::load_embedded();
        assert_eq!(&KMD_DATA[0..4], b"KMD\x00");
        assert!(kms.header.csvlk_count > 0);
        assert!(kms.header.app_item_count > 0);
        assert!(kms.header.kms_item_count > 0);
        assert!(kms.header.sku_item_count > 0);
        assert!(kms.header.host_build_count > 0);
    }

    #[test]
    fn csvlk_data_valid() {
        let kms = KmsData::load_embedded();
        for csvlk in &kms.csvlk_data {
            assert!(csvlk.min_key_id < csvlk.max_key_id);
            assert!(csvlk.group_id > 0);
        }
    }

    #[test]
    fn host_builds_valid() {
        let kms = KmsData::load_embedded();
        assert!(!kms.host_builds.is_empty());
        for hb in &kms.host_builds {
            assert!(hb.build_number > 0);
            assert!(hb.platform_id > 0);
        }
    }

    #[test]
    fn string_lookup_works() {
        let kms = KmsData::load_embedded();
        // Check that at least one app item has a non-empty name
        let has_name = kms.app_items.iter().any(|item| {
            !kms.get_string(item.name_offset).is_empty()
        });
        assert!(has_name);
    }

    #[test]
    fn kms_items_have_guids() {
        let kms = KmsData::load_embedded();
        for item in &kms.kms_items {
            assert_ne!(item.guid, Guid::ZERO);
        }
    }
}
