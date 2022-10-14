use std::fs::File;
use std::error::Error as StdError;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write;
use clap::Arg;
use clap::Command;
use pelite::Error;
use pelite::FileMap;
use pelite::pattern as pat;
use pelite::pe32::*;
use memmem::{Searcher, TwoWaySearcher};
use pelite::pe32::Va;
use regex::Regex;
use utf16string::WStr;
use patternscan::scan;
use std::io::Cursor;
use pelite::pattern::Atom:: Byte;

fn get_import_function_va(
    // Find virtual address of function "search_function_name" in module "search_dll_name"
    // Return Result<Va> 
    pe: &PeFile,
    search_dll_name: &str,
    search_function_name: &str,
) -> pelite::Result<Va> {
    // Access the import directory
    let imports = pe.imports()?;
    // Iterate over the import descriptors
    for desc in imports {
        match desc.dll_name() {
            Ok(dll_name) => {
                if dll_name == search_dll_name {
                    let iat = desc.iat()?;
                    let int = desc.int()?;
                    let mut index_function = 0;
                    let dll_iat_rva: Rva =
                        pe.rva_to_va(desc.image().FirstThunk).unwrap_or_default();
                    for (va, _import) in Iterator::zip(iat, int) {    
                        if *va > 0 {
                            match pe.derva_c_str(*va + 0x2) {
                                Ok(function_name) => {
                                    if search_function_name == function_name.to_str().unwrap() {
                                        return Ok(dll_iat_rva + index_function * 0x4);
                                    }
                                }
                                Err(_) => (),
                            }
                            index_function += 1;
                        }
                    }
                }
            }
            Err(_) => (),
        }
    }
    Err(Error::Invalid)
}

fn read_utf16_string_va(pe: &PeFile, va: Va) -> Result<String,  Box<dyn StdError>> {
    // ugly but functional
    // Read utf16le wstr from virtual address and remove some special chars.
    // Return String or StdError
    let data = pe.read(va, 2, 1).unwrap_or_default();
    if data.len() > 0{
        let search = TwoWaySearcher::new("\x00\x00".as_bytes());
        let mut stop_index = search.search_in(data).unwrap_or(0);
        if stop_index == 0{
            Err("Error: Stop index is 0")?;
        }
        else if let 1=stop_index%2 {
            stop_index+= 1;
        }
        let re = Regex::new(r"[^a-zA-Z\d — -./\\]").unwrap();
        let mut str_string =  WStr::from_utf16le(&data[..stop_index]).unwrap().to_utf8();
        str_string = re.replace_all(&str_string, "").to_string();
        return Ok(str_string);
    }
    Err("Error: No data")?
}

fn read_utf16_string(raw: &[u8]) -> Result<String,  Box<dyn StdError>> {
    // Read utf16le wstr from &[u8] and remove some special chars.
    // Return String or StdError
    let re = Regex::new(r"[^a-zA-Z0-9 — - - . / \\]").unwrap();
    let mut str_string =  WStr::from_utf16le(&raw).unwrap().to_utf8();
    str_string = re.replace_all(&str_string, "").to_string();
    Ok(str_string)
}

fn find_offset_from_calling_function_sig_pattern(pe: &PeFile, pat:  &[pelite::pattern::Atom], offset: u32) -> Result<u32,  Box<dyn StdError>>{
    // Find call address based on bytes pattern.
    let mut index_pat = [0; 2];
    if pe.scanner().finds_code(pat, &mut index_pat){
        let va_to_func_call:Va = pe.rva_to_va(index_pat[1]).unwrap_or_default();
        let call_offset: Va = pe.derva_copy(index_pat[1]).unwrap_or_default();
        let push_str_loc_address:Va = va_to_func_call.overflowing_add(call_offset).0  + offset;
        let read_bytes = pe.read_bytes(push_str_loc_address).unwrap();
        let offset =  u32::from_le_bytes(read_bytes[..4].try_into().unwrap_or_default());
        if offset > 0 {
            return Ok(offset);
        }
        else{
            Err("Error: Offset is Null")?
        }
    }
    Err("Error: Pattern not found")?
}

fn decode_decompress_lznt1_pe(f: &File) -> Result<Vec<u8>,  Box<dyn StdError>>{
    // Decode (bruteforce 1 byte key) and decompress lznt1 PE file
    let mut reader = BufReader::new(f);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).unwrap();
    // Bruteforce Key (1 byte)
    for key in 0x00..0xff{
        let mut buffer_decrypted: Vec<u8> = Vec::new();
        for value in &buffer {
            buffer_decrypted.push(value.overflowing_add(key).0 & 0xff as u8);
        }
        let mut patterns: Vec<&[u8]> = Vec::new();
        // lznt1 PE compressed signatures
        patterns.push(&[0xcc, 0xb9, 0x00, 0x4d, 0x5a, 0x90]);
        patterns.push(&[0xfc, 0xb9, 0x00, 0x4d, 0x5a, 0x90]);
        patterns.push(&[0x53, 0xb9, 0x00, 0x4d, 0x5a, 0x90]);
        // search for patterns
        for pattern in patterns{
            let search = TwoWaySearcher::new(&pattern);
            let index_start_pe = search.search_in(&buffer_decrypted).unwrap_or(0);
            if index_start_pe != 0 {
                // if one of lznt1 PE pattern is found decompress the PE 
                println!(" [+] ==> The decryption Key is: 0x{:x?}", key);
                let pe_buffer = buffer_decrypted[index_start_pe..].to_vec();
                return Ok(lzxpress::lznt1::decompress(&pe_buffer).unwrap_or_default());
            }
        }
    }
    Err("Error: Cannot decode and decompress PE")?
}

fn find_extra_strings(pe: &PeFile) -> Result<Vec<(u32, String, String)>,  Box<dyn StdError>>{
    // This function uses different scan patterns found by reverse engineering samples retrieved from VirusTotal.
    // This method try to extract others interesting fields not included in the main configuration

    let mut vec_results: Vec<(u32, String, String)> = Vec::new();
    let mut patterns: Vec<(u32, &str, Vec<pat::Atom>, usize)> = Vec::new();
    //-------------------------------------------------------------------------------
    // Find Mutex from CreateMutex (KERNEL32.dll) import
    let create_mutex_va = get_import_function_va(&pe, "KERNEL32.dll", "CreateMutexW").unwrap_or_default();
    let create_mutex_va_le_bytes =  create_mutex_va.to_le_bytes();
    let create_mutex_pattern:&[pelite::pattern::Atom] = pat!("56 68' [4] 6A 00 6A 00 FF 15");
    let create_mutex_va_as_pat: &[pelite::pattern::Atom]  = &[Byte(create_mutex_va_le_bytes[0]),  Byte(create_mutex_va_le_bytes[1]), Byte(create_mutex_va_le_bytes[2]), Byte(create_mutex_va_le_bytes[3])];
    let win_http_open_request_pattern = [create_mutex_pattern, create_mutex_va_as_pat].concat();
    // Raw pattern = "56 68' ?? ?? ?? ?? 6A 00  6A 00 FF 15 + create_mutex_va"
    patterns.push((9, "[-] Mutex", win_http_open_request_pattern, 1));
    
    //-------------------------------------------------------------------------------
    // Find C2 Path and Verb (Method ?) from WinHttpOpenRequest (WINHTTP.dll) import
    let win_http_open_request_va = get_import_function_va(&pe, "WINHTTP.dll", "WinHttpOpenRequest").unwrap_or_default();
    let win_http_open_request_va_le_bytes =  win_http_open_request_va.to_le_bytes();
    // Raw pattern = "68' ? ? ? ? 68' ? ? ? ?(FF 36 | 50 ) FF 15" + win_http_open_request_va
    let win_http_open_request_pattern:&[pelite::pattern::Atom] = pat!("68' [4] 68' [4] (FF 36 | 50 ) FF 15");
    let win_http_open_request_va_as_pat: &[pelite::pattern::Atom]  = &[Byte(win_http_open_request_va_le_bytes[0]),  Byte(win_http_open_request_va_le_bytes[1]), Byte(win_http_open_request_va_le_bytes[2]), Byte(win_http_open_request_va_le_bytes[3])];
    let win_http_open_request_pattern = [win_http_open_request_pattern, win_http_open_request_va_as_pat].concat();
    patterns.push((6, "[-] C2 Path", win_http_open_request_pattern.clone(), 1));
    patterns.push((7, "[-] Verb", win_http_open_request_pattern, 2));
    //--------------------------------------- ----------------------------------------
    // Find Configuration registry key from RegQueryValueExW (ADVAPI32.dll) import
    let reg_query_value_ex_w_va = get_import_function_va(&pe, "ADVAPI32.dll", "RegQueryValueExW").unwrap_or_default();
    let reg_query_value_ex_w_va_le_bytes =  reg_query_value_ex_w_va.to_le_bytes();
    let reg_query_value_ex_w_pattern = pat!("68' [4] (50 | FF 75 E8 ) FF 15");
    let reg_query_value_ex_w_va_as_pat: &[pelite::pattern::Atom]  = &[Byte(reg_query_value_ex_w_va_le_bytes[0]),  Byte(reg_query_value_ex_w_va_le_bytes[1]), Byte(reg_query_value_ex_w_va_le_bytes[2]), Byte(reg_query_value_ex_w_va_le_bytes[3])];
    let reg_query_value_ex_w_pattern = [reg_query_value_ex_w_pattern, reg_query_value_ex_w_va_as_pat].concat();
    patterns.push((0, "[-] HyperBro Configuration registry key", reg_query_value_ex_w_pattern, 1));
    //--------------------------------------- ----------------------------------------
    
    // Find Named Pipe from WaitNamedPipeW (KERNEL32.dll) import
    let wait_named_pipe_w_va = get_import_function_va(&pe, "KERNEL32.dll", "WaitNamedPipeW").unwrap_or_default();
    let wait_named_pipe_w_va_le_bytes =  wait_named_pipe_w_va.to_le_bytes();
    let wait_named_pipe_w_pattern:&[pelite::pattern::Atom] = pat!("6A FF 68' [4] [5-11] FF 15");
    let wait_named_pipe_va_as_pat: &[pelite::pattern::Atom]  = &[Byte(wait_named_pipe_w_va_le_bytes[0]),  Byte(wait_named_pipe_w_va_le_bytes[1]), Byte(wait_named_pipe_w_va_le_bytes[2]), Byte(wait_named_pipe_w_va_le_bytes[3])];
    let wait_named_pipe_w_pattern = [wait_named_pipe_w_pattern, wait_named_pipe_va_as_pat].concat();
    patterns.push((8, "[-] Named Pipe", wait_named_pipe_w_pattern, 1));
    //--------------------------------------- ----------------------------------------
    // Search strings from patterns
    for item in patterns.into_iter() {
        let mut index_matched_pattern = [0; 8];
        let mut matches = pe.scanner().matches(&item.2, pe.headers().image_range());       
        while matches.next(&mut index_matched_pattern){
            let str_offset:Va=pe.derva_copy(index_matched_pattern[item.3]).unwrap_or(0);
            if pe.derva_copy(index_matched_pattern[item.3]).unwrap_or(0) != 0 {
                let extracted_string = read_utf16_string_va(pe, str_offset);
                match extracted_string {
                    Ok(extracted_string) => vec_results.push((item.0, item.1.to_string(), extracted_string)),
                    Err(_) => (),
                };
            }
        }
    }
    if vec_results.is_empty(){
        Err("Error: Cannot find extra strings")?
    }
     Ok(vec_results)
}

fn extract_config(pe: &PeFile) -> Result<Vec<(u32, String, String)>,  Box<dyn StdError>>{
    // Extract main configuration args
    // This function also uses different scan patterns found by reverse engineering samples retrieved from VirusTotal.
    let mut patterns: Vec<(&[pelite::pattern::Atom], &[pelite::pattern::Atom])> = Vec::new();
    // patterns = (Config size pattern, Address to config pattern)
    patterns.push((pat!("C7 45 ?' ? ? ? ? 89 7D CC"), pat!("68' ? ? ? ? 8D 45 D0")));
    /*  pattern C7 45 ?' ? ? ? ? 89 7D CC
        .text:100088F2                 mov     [ebp+cbData], 200h <= size of config
        .text:100088F9                 mov     [ebp+var_34], edi
        .text:100088FC                 mov     [ebp+Type], 3

        pattern 68' ? ? ? ? 8D 45 D0
        .text:10008921                 push    offset Src <= offset to config
        .text:10008926                 lea     eax, [ebp+Type]
    */
    patterns.push((pat!("80 7D 08 00 C7 85 ? ? ? ?' ? ? ? ?"), pat!("68' ? ? ? ? E8 ? ? ? ? 8D 46 38")));
    /*  pattern 80 7D 08 00 C7 85 ? ? ? ?' ? ? ? ?
        .text:1000766D                 cmp     [ebp+arg_0], 0
        .text:10007671                 mov     [ebp+cbData], 200h <= size of config

        pattern 68' ? ? ? ? E8 ? ? ? ? 8D 46 38
        .text:10007799                 push    [ebp+cbData] 
        .text:1000779F                 push    offset Src   <= offset to config
        .text:100077A4                 call    sub_1000256A
    */
    let size_config;
    let config_offset;
    let mut index_matched_pattern_config_size = [0; 2];
    let mut index_matched_pattern_config = [0; 2];
    let mut patterns_found = false;
    for item in patterns.into_iter() {
        if pe.scanner().finds_code(item.0, &mut index_matched_pattern_config_size) && pe.scanner().finds_code(item.1, &mut index_matched_pattern_config){
            patterns_found = true;
            break;
        }
    }
    // Try another scan method to find config
    if !patterns_found{
        config_offset = find_offset_from_calling_function_sig_pattern(pe, pat!("E8' ? ? ? ? E8 ? ? ? ? 53"), 0xc3 + 0x5).unwrap_or_default();
        size_config = find_offset_from_calling_function_sig_pattern(pe, pat!("E8' ? ? ? ? E8 ? ? ? ? 53"), 0x20).unwrap_or_default();
        if config_offset == 0 || size_config == 0 {
            Err("Error: Pattern not found")?
        }
    }
    else {
        size_config = pe.derva_copy(index_matched_pattern_config_size[1]).expect("Cannot get config size !");
        config_offset= pe.derva_copy(index_matched_pattern_config[1]).expect("Cannot get config offset !");
    }
    let mut config_data = pe.read(config_offset, size_config as usize, 1).unwrap();
    config_data = &config_data[4..size_config as usize]; // Skip 4 useless bytes
    let pattern = "00 00 00"; //End of utf-16 string
    let locs = scan(Cursor::new(config_data), &pattern).expect("Cannot find utf-16 strings in config buffer :'(");
    //Return indexes location that match utf16 wstrings
    let mut config: Vec<String> = Vec::new();
    let mut lastloc= 0;
    for loc in locs{
        if lastloc < loc{
            let mut stop_index = loc;
            if let 1=(loc-lastloc)%2{
                stop_index+= 1;
            };
            if stop_index <= config_data.len(){
                let str_extracted = read_utf16_string(&config_data[lastloc..stop_index]).unwrap();
                if str_extracted.len() > 0{
                    config.push(str_extracted);
                }
                lastloc = stop_index+2;
            }
        }  
    }
    let mut results: Vec<(u32, String, String)> = Vec::new();
    results.push((1, "[-] Legit loader".to_string(), config.get(0).unwrap().to_string()));
    results.push((2, "[-] First stage".to_string(), config.get(1).unwrap().to_string()));
    results.push((3, "[-] Second stage".to_string(), config.get(2).unwrap().to_string()));
    results.push((4, "[-] Windows service name".to_string(), config.get(3).unwrap().to_string()));
    results.push((5, "[-] C2 address".to_string(), config.get(10).unwrap().to_string()));
    Ok(results)
}
fn main() {
    let args_clap = Command::new("hyperbro_config_extractor")
        .override_usage("hyperbro_config_extractor [-i stage2_file] [-o output of extracted PE]")
        .arg(
            Arg::new("i")
                .short('i')
                .help("Path of stage2 (thumb.dat)")
                .takes_value(true)
                .required(true)
                .multiple_occurrences(false)
                .number_of_values(1),
        )
        .arg(
            Arg::new("o")
                .short('o')
                .help("Path to save extracted and uncompressed PE")
                .takes_value(true)
                .required(true)
                .multiple_occurrences(false)
                .number_of_values(1),
        ).get_matches();

    println!(" /!\\ --- HyperBro config extractor --- /!\\");
    let input_path = &args_clap.value_of("i").expect("-i incorrect value returned");
    let output_path = &args_clap.value_of("o").expect("-o incorrect value returned");
    let input_file = File::open(input_path).expect("Erorr opening input file.");
    let mut output_file = BufWriter::new(File::create(output_path).expect("Error openning output BufWriter"));
    let extracted_pe = decode_decompress_lznt1_pe(&input_file).expect("Error while extracting PE from decrypted input file.");
    output_file.write_all(&extracted_pe).expect("Error occured while writing extracted PE to output file.");
    println!(" /!\\ --- Successfully exported PE to : {0} --- /!\\", output_path);
    drop(output_file);
    let pe_file_map = FileMap::open(output_path).expect("Error: Cannot map PE.");
    let hyperbro_pe = PeFile::from_bytes(&pe_file_map).expect("Error cannot open PE with PeFile.");
    let mut results: Vec<(u32, String, String)> = Vec::new();
    let mut main_config = extract_config(&hyperbro_pe).unwrap_or_default();
    let mut extra_config = find_extra_strings(&hyperbro_pe).unwrap_or_default();
    match (main_config.len() > 0, extra_config.len() > 0) {
        (false, false) => {
            println!("No config found, you should try to update pattern !");
            println!("You can also try to find utf-16le string from extracted PE {0}", output_path);
        }
        (true, true) => {
            results.append(&mut main_config);
            results.append(&mut extra_config);
        },
        (true, false) =>  results.append(&mut main_config),
        (false, true) => results.append(&mut extra_config),
    }
    results.sort_by_key(|k| k.0);
    results.dedup_by_key(|k| k.0);
    for result in results.clone(){
        println!(" {0}: {1}", result.1, result.2);
    }
}