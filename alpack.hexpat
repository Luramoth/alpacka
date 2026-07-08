struct header {
    u64 MagicNumber;
    u64 Version;
    u64 EntryCount;
    u64 DataOffset;
    u64 StringTableOffset;
    u64 IndexOffset;
    u64 IndexChecksum;
    u64 archive_salt;
    u64 Reserved            [[color("f9f9f9")]];
};

struct entry {
    u64 custom1;
    u64 custom2;
    u64 DataOffset;
    u64 CompressedSize;
    u64 OriginalSize;
    u64 CompressionType;
    u64 NameOffset;
    u64 NameLength;
    u64 encryption_type;
    u64 nonce;
    u64 Reserved            [[color("f9f9f9")]];
    
    u8 data[CompressedSize] @ DataOffset + parent.Header.DataOffset;
    
    char name[NameLength] @ parent.Header.StringTableOffset + NameOffset;
};

struct alpack {
    header Header;
    
    entry entries[Header.EntryCount] @ Header.IndexOffset;
};

alpack Alpack @ 0x00;