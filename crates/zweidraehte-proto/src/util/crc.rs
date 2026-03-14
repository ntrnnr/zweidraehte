pub fn crc16_ccitt(buf: &[u8]) -> u16 {
    let mut crc: u16 = 0x1d0f;

    for b in buf {
        crc = crc >> 8 | (crc & 0xff) << 8;
        crc ^= *b as u16;
        crc ^= (crc >> 4) & 0xF;
        crc ^= crc << 12;
        crc ^= (crc & 0xff) << 5;
        crc &= 0xffff;
    }

    crc
}
