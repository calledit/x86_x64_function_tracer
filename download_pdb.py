import pefile
import argparse
import struct
import os
import urllib.request

MICROSOFT_SYMBOL_STORE = "https://msdl.microsoft.com/download/symbols/"

def get_guid(dll):
    # https://gist.github.com/steeve85/2665503
    # ugly code, isn't it ?
    try:
        # dll = pefile.PE(dll_path)
        rva = dll.DIRECTORY_ENTRY_DEBUG[0].struct.AddressOfRawData
        tmp = ''
        tmp += '%0.*X' % (8, dll.get_dword_at_rva(rva+4))
        tmp += '%0.*X' % (4, dll.get_word_at_rva(rva+4+4))
        tmp += '%0.*X' % (4, dll.get_word_at_rva(rva+4+4+2))
        x = dll.get_word_at_rva(rva+4+4+2+2)
        tmp += '%0.*X' % (4, struct.unpack('<H',struct.pack('>H',x))[0])
        x = dll.get_word_at_rva(rva+4+4+2+2+2)
        tmp += '%0.*X' % (4, struct.unpack('<H',struct.pack('>H',x))[0])
        x = dll.get_word_at_rva(rva+4+4+2+2+2+2)
        tmp += '%0.*X' % (4, struct.unpack('<H',struct.pack('>H',x))[0])
        x = dll.get_word_at_rva(rva+4+4+2+2+2+2+2)
        tmp += '%0.*X' % (4, struct.unpack('<H',struct.pack('>H',x))[0])
        tmp += '%0.*X' % (1, dll.get_word_at_rva(rva+4+4+2+2+2+2+2+2))
    except AttributeError as e:
        # print ('Error appends during %s parsing' % dll_path)
        print (e)
        return None
    return tmp.upper()
    
def get_pdb_name(file_name):
    basename = os.path.basename(file_name)
    basic_name, ext = os.path.splitext(basename)
    
    return basic_name + ".pdb"

def get_pdb_from_microsoft(file_name):
    basename = os.path.basename(file_name)
    basic_name, ext = os.path.splitext(basename)
    
    pdb_file_name = get_pdb_name(file_name)
    output_filename = "pdbs" + os.sep + pdb_file_name
    
    if not os.path.exists(output_filename):
        pe_info = pefile.PE(name=file_name, fast_load=True)
        pe_info.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']])
        
        guid = get_guid(pe_info)
        url = MICROSOFT_SYMBOL_STORE +pdb_file_name +"/" + guid + "/" + pdb_file_name
        print("get pdb from microsoft:", url, guid)
        try:
            urllib.request.urlretrieve(url, output_filename)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                open(output_filename, "w").close()
    
    return output_filename


if __name__ == '__main__':
    
    os.makedirs('pdbs', exist_ok=True)
    
    parser = argparse.ArgumentParser(description='shows binary call trace files')
    parser.add_argument('--file', type=str, required=True, help='Binary trace file')
    args = parser.parse_args()
    
    get_pdb_from_microsoft(args.file)