import struct
path=r"C:\Users\FSOS\Downloads\vulkan-main\vulkan-main\build-msvc\RobloxPlayerBeta_dump.dll"
with open(path,'rb') as f:
    dos=f.read(64)
    e_lfanew=struct.unpack_from('<I',dos,0x3c)[0]
    f.seek(e_lfanew)
    signature=f.read(4)
    if signature!=b'PE\0\0':
        raise SystemExit('not PE')
    machine, num_sections=struct.unpack('<HH',f.read(4))
    timestamp, symptr, syms, optsize=struct.unpack('<IIIH',f.read(14))
    size_optional=optsize
    characteristics=struct.unpack('<H',f.read(2))[0]
    optional=f.read(size_optional)
    magic=struct.unpack_from('<H',optional,0)[0]
    if magic==0x20b:
        image_base=struct.unpack_from('<Q',optional,24)[0]
    else:
        image_base=struct.unpack_from('<I',optional,28)[0]
    section_offset = e_lfanew + 24 + size_optional
    section_entry_size=40
    sections=[]
    f.seek(section_offset)
    for i in range(num_sections):
        data=f.read(section_entry_size)
        name=data[:8].rstrip(b'\0').decode(errors='ignore')
        virtual_size, virtual_address, size_raw, ptr_raw=struct.unpack_from('<IIII',data,8)
        sections.append((name, virtual_size, virtual_address, size_raw, ptr_raw))
    print('ImageBase=',hex(image_base))
    offsets=[13976547,13976647,13053098]
    for off in offsets:
        for name,vs,va,sr,pr in sections:
            if pr<=off<pr+sr:
                rva=va + (off-pr)
                print(f'offset {off} -> section {name}, RVA {hex(rva)}, VA {hex(image_base+rva)}')
                break
        else:
            print(f'offset {off}: not in any section')
