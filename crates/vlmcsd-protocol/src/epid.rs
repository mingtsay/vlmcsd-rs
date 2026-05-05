use vlmcsd_kmsdata::KmsData;

const LCID_LIST: &[u16] = &[
    1078, 1052, 1025, 2049, 3073, 4097, 5121, 6145, 7169, 8193, 9217, 10241, 11265, 12289, 13313,
    14337, 15361, 16385, 1067, 1068, 2092, 1069, 1059, 1093, 5146, 1026, 1027, 1028, 2052, 3076,
    4100, 5124, 1050, 4122, 1029, 1030, 1125, 1043, 2067, 1033, 2057, 3081, 4105, 5129, 6153,
    7177, 8201, 9225, 10249, 11273, 12297, 13321, 1061, 1080, 1065, 1035, 1036, 2060, 3084, 4108,
    5132, 6156, 1079, 1110, 1031, 2055, 3079, 4103, 5127, 1032, 1095, 1037, 1081, 1038, 1039,
    1057, 1040, 2064, 1041, 1099, 1087, 1111, 1042, 1088, 1062, 1063, 1071, 1086, 2110, 1100,
    1082, 1153, 1102, 1104, 1044, 2068, 1045, 1046, 2070, 1094, 1131, 2155, 3179, 1048, 1049,
    9275, 4155, 5179, 3131, 1083, 2107, 8251, 6203, 7227, 1103, 2074, 6170, 3098, 7194, 1051,
    1060, 1034, 2058, 3082, 4106, 5130, 6154, 7178, 8202, 9226, 10250, 11274, 12298, 13322,
    14346, 15370, 16394, 17418, 18442, 19466, 20490, 1089, 1053, 2077, 1114, 1097, 1092, 1098,
    1054, 1074, 1058, 1056, 1091, 2115, 1066, 1106, 1076, 1077,
];

pub fn generate_random_epid(kms_data: &KmsData, csvlk_index: usize, seed: u64) -> String {
    let mut rng = SimpleRng::new(seed);

    let host_build_idx = rng.next_u32() as usize % kms_data.host_builds.len();
    let host_build = kms_data.host_builds[host_build_idx].build_number;
    let platform_id = kms_data.get_platform_id(host_build);

    let csvlk = &kms_data.csvlk_data[csvlk_index.min(kms_data.csvlk_data.len() - 1)];

    let key_range = csvlk.max_key_id - csvlk.min_key_id;
    let key_id = (rng.next_u32() % key_range) + csvlk.min_key_id;

    let lcid = LCID_LIST[rng.next_u32() as usize % LCID_LIST.len()];

    let release_date = kms_data.get_release_date(host_build);
    let min_time = if csvlk.release_date > release_date {
        csvlk.release_date
    } else {
        release_date
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let max_time = now.max(1538922811);

    let kms_time = if max_time > min_time {
        (rng.next_u32() as i64 % (max_time - min_time)) + min_time
    } else {
        min_time
    };

    let (day_of_year, year) = unix_to_day_year(kms_time);

    format!(
        "{:05}-{:05}-{:03}-{:06}-03-{}-{}.0000-{:03}{}",
        platform_id,
        csvlk.group_id,
        key_id / 1000000,
        key_id % 1000000,
        lcid,
        host_build,
        day_of_year,
        year,
    )
}

fn unix_to_day_year(timestamp: i64) -> (u32, u32) {
    const SECS_PER_DAY: i64 = 86400;
    let days_since_epoch = timestamp / SECS_PER_DAY;

    let mut year = 1970i32;
    let mut remaining_days = days_since_epoch as i32;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    ((remaining_days + 1) as u32, year as u32)
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        SimpleRng {
            state: seed ^ 0x6c62272e07bb0142,
        }
    }

    fn next_u32(&mut self) -> u32 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlmcsd_kmsdata::KmsData;

    #[test]
    fn generate_epid_format() {
        let kms = KmsData::load_embedded();
        let epid = generate_random_epid(&kms, 0, 12345);
        // ePID format: XXXXX-XXXXX-XXX-XXXXXX-03-LCID-BUILD.0000-DDDYYYY
        let parts: Vec<&str> = epid.split('-').collect();
        assert!(parts.len() >= 7, "ePID has wrong number of parts: {}", epid);
        assert_eq!(parts[4], "03");
    }

    #[test]
    fn generate_epid_deterministic() {
        let kms = KmsData::load_embedded();
        let epid1 = generate_random_epid(&kms, 0, 42);
        let epid2 = generate_random_epid(&kms, 0, 42);
        assert_eq!(epid1, epid2);
    }

    #[test]
    fn generate_epid_different_seeds() {
        let kms = KmsData::load_embedded();
        let epid1 = generate_random_epid(&kms, 0, 1);
        let epid2 = generate_random_epid(&kms, 0, 2);
        assert_ne!(epid1, epid2);
    }
}
