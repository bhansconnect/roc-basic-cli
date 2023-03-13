#![allow(non_snake_case)]

mod file_glue;
mod glue;

use core::alloc::Layout;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use glue::Metadata;
use roc_std::{RocDict, RocList, RocResult, RocStr};
use std::borrow::{Borrow, Cow};
use std::cell::RefCell;
use std::ffi::OsStr;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use bumpalo::Bump;
use rustyline::completion::FilenameCompleter;
use rustyline::error::ReadlineError;
use rustyline::hint::HistoryHinter;
use rustyline::{
    Completer, CompletionType, Config, Editor, Helper, Highlighter, Hinter, Validator,
};

use file_glue::ReadErr;
use file_glue::WriteErr;

#[cfg(target_os = "macos")]
static EXTENSION: &str = "dylib";
#[cfg(target_os = "linux")]
static EXTENSION: &str = "so.1.0";

thread_local!(static BUMP: RefCell<Bump> = RefCell::new(Bump::new()));

thread_local!(static ARGS: RefCell<Vec<String>> = RefCell::new(vec![]));

extern "C" {
    #[link_name = "roc__mainForHost_1_exposed_generic"]
    fn roc_main(output: *mut u8);

    #[link_name = "roc__mainForHost_size"]
    fn roc_main_size() -> i64;

    #[link_name = "roc__mainForHost_1__Fx_caller"]
    fn call_Fx(flags: *const u8, closure_data: *const u8, output: *mut u8);

    #[allow(dead_code)]
    #[link_name = "roc__mainForHost_1__Fx_size"]
    fn size_Fx() -> i64;

    #[link_name = "roc__mainForHost_1__Fx_result_size"]
    fn size_Fx_result() -> i64;
}

#[derive(Helper, Completer, Hinter, Highlighter, Validator)]
struct RustyLineHelper {
    #[rustyline(Completer)]
    completer: FilenameCompleter,
    #[rustyline(Hinter)]
    hinter: HistoryHinter,
}

#[no_mangle]
pub extern "C" fn rust_main() {
    // Disable panic printout.
    std::panic::set_hook(Box::new(|_| {}));

    let config = Config::builder()
        .history_ignore_space(true)
        .completion_type(CompletionType::List)
        .build();
    let helper = RustyLineHelper {
        completer: FilenameCompleter::new(),
        hinter: HistoryHinter {},
    };
    let mut rl = Editor::with_config(config).unwrap();
    rl.set_helper(Some(helper));
    _ = rl.load_history("/tmp/history.txt");
    loop {
        // Request input.

        let readline = rl.readline(">> ");
        let input = match readline {
            Ok(line) => {
                _ = rl.add_history_entry(line.as_str());
                line
            }
            Err(ReadlineError::Interrupted) => {
                break;
            }
            Err(ReadlineError::Eof) => {
                break;
            }
            Err(err) => {
                println!("Readline hit unexpected error: {:?}", err);
                break;
            }
        };
        println!("");

        // Process args.
        let input_path = ARGS.with(|args| {
            *args.borrow_mut() = input.trim().split(" ").map(|x| x.to_string()).collect();
            args.borrow()[0].to_owned()
        });
        let input_path = Path::new(&input_path);
        if !input_path.is_file() {
            println!("Could not find input file\n\n");
            continue;
        }
        if input_path.extension() != Some(OsStr::new("roc")) {
            println!("Expected input file to have the `.roc` extension\n\n");
            continue;
        }

        // Run roc to compile lib.
        let out = Command::new("roc")
            .args(["build", "--lib", "--prebuilt-platform=true"])
            .arg(input_path)
            .output();

        if let Err(err) = out {
            println!("Failed to run roc to compile plugin: {:?}\n\n", err);
            continue;
        }
        let out = out.unwrap();
        let stdout = std::str::from_utf8(&out.stdout).expect("roc outputted invalid utf8");
        if !out.status.success() || !stdout.contains("successfully building") {
            println!("Roc command failed during compilation:");
            println!("stdout was:");
            std::io::stdout().write_all(&out.stdout).unwrap();
            println!("\nstderr was:");
            std::io::stdout().write_all(&out.stderr).unwrap();
            println!("\n\n");
            continue;
        }
        let (_, output_file) = stdout.rsplit_once(' ').expect("Failed to parse roc output");
        let output_file = output_file.trim();
        let output_file = Path::new(output_file).with_extension(EXTENSION);
        dbg!(output_file);

        // Load plugin.

        // Setup new bumpalo bump for memory allocations.
        BUMP.with(|bump| {
            bump.borrow_mut().reset();
            // Set arbitrary limit for processes of 1MB.
            bump.borrow_mut().set_allocation_limit(Some(1024 * 1024));
        });

        // Run app with calls to plugin.
        let res = std::panic::catch_unwind(|| {
            let size = unsafe { roc_main_size() } as usize;
            let layout = Layout::array::<u8>(size).unwrap();

            unsafe {
                let buffer = BUMP
                    .with(|bump| bump.borrow().alloc_layout(layout))
                    .as_ptr();

                roc_main(buffer);

                call_the_closure(buffer);
            }
        });
        if let Err(x) = res {
            if let Some(string) = x.downcast_ref::<String>() {
                println!("Plugin crashed with message:\t{}\n", string);
            } else {
                println!("Plugin crashed with unknown type:\t{:?}\n", x.type_id());
            }
            println!("Cleaning up allocations and continuing.")
        }
        println!("\n");
    }
    _ = rl.save_history("/tmp/history.txt");
}

#[no_mangle]
pub unsafe extern "C" fn roc_alloc(size: usize, alignment: u32) -> *mut c_void {
    BUMP.with(|bump| {
        bump.borrow()
            .alloc_layout(Layout::from_size_align(size, alignment as usize).unwrap())
    })
    .as_ptr() as _
}

#[no_mangle]
pub unsafe extern "C" fn roc_realloc(
    c_ptr: *mut c_void,
    new_size: usize,
    old_size: usize,
    alignment: u32,
) -> *mut c_void {
    let new_loc = BUMP
        .with(|bump| {
            bump.borrow()
                .alloc_layout(Layout::from_size_align(new_size, alignment as usize).unwrap())
        })
        .as_ptr() as _;

    roc_memcpy(new_loc, c_ptr, old_size);

    new_loc
}

#[no_mangle]
pub unsafe extern "C" fn roc_dealloc(_c_ptr: *mut c_void, _alignment: u32) {}

#[no_mangle]
pub unsafe extern "C" fn roc_panic(msg: &RocStr, _tag_id: u32) {
    panic!("{}", msg.as_str());
}

#[cfg(unix)]
#[no_mangle]
pub unsafe extern "C" fn roc_getppid() -> libc::pid_t {
    libc::getppid()
}

#[cfg(unix)]
#[no_mangle]
pub unsafe extern "C" fn roc_mmap(
    addr: *mut libc::c_void,
    len: libc::size_t,
    prot: libc::c_int,
    flags: libc::c_int,
    fd: libc::c_int,
    offset: libc::off_t,
) -> *mut libc::c_void {
    libc::mmap(addr, len, prot, flags, fd, offset)
}

#[cfg(unix)]
#[no_mangle]
pub unsafe extern "C" fn roc_shm_open(
    name: *const libc::c_char,
    oflag: libc::c_int,
    mode: libc::mode_t,
) -> libc::c_int {
    libc::shm_open(name, oflag, mode as libc::c_uint)
}

#[no_mangle]
pub unsafe extern "C" fn roc_memcpy(dst: *mut c_void, src: *mut c_void, n: usize) -> *mut c_void {
    libc::memcpy(dst, src, n)
}

#[no_mangle]
pub unsafe extern "C" fn roc_memset(dst: *mut c_void, c: i32, n: usize) -> *mut c_void {
    libc::memset(dst, c, n)
}

unsafe fn call_the_closure(closure_data_ptr: *const u8) -> u8 {
    let size = size_Fx_result() as usize;
    let layout = Layout::array::<u8>(size).unwrap();
    let buffer = BUMP.with(|bump| bump.borrow().alloc_layout(layout));

    call_Fx(
        // This flags pointer will never get dereferenced
        MaybeUninit::uninit().as_ptr(),
        closure_data_ptr,
        buffer.as_ptr(),
    );

    0
}

#[no_mangle]
pub extern "C" fn roc_fx_envDict() -> RocDict<RocStr, RocStr> {
    std::env::vars_os()
        .map(|(key, val)| {
            (
                RocStr::from(key.to_string_lossy().borrow()),
                RocStr::from(val.to_string_lossy().borrow()),
            )
        })
        .collect()
}

#[no_mangle]
pub extern "C" fn roc_fx_args() -> RocList<RocStr> {
    ARGS.with(|args| args.borrow().iter().map(|x| x.as_str().into()).collect())
}

#[no_mangle]
pub extern "C" fn roc_fx_envVar(roc_str: &RocStr) -> RocResult<RocStr, ()> {
    match std::env::var_os(roc_str.as_str()) {
        Some(os_str) => RocResult::ok(RocStr::from(os_str.to_string_lossy().borrow())),
        None => RocResult::err(()),
    }
}

#[no_mangle]
pub extern "C" fn roc_fx_setCwd(roc_path: &RocList<u8>) -> RocResult<(), ()> {
    match std::env::set_current_dir(path_from_roc_path(roc_path)) {
        Ok(()) => RocResult::ok(()),
        Err(_) => RocResult::err(()),
    }
}

#[no_mangle]
pub extern "C" fn roc_fx_processExit(exit_code: u8) {
    panic!("Process exited with code: {}", exit_code);
}

#[no_mangle]
pub extern "C" fn roc_fx_exePath(_roc_str: &RocStr) -> RocResult<RocList<u8>, ()> {
    match std::env::current_exe() {
        Ok(path_buf) => RocResult::ok(os_str_to_roc_path(path_buf.as_path().as_os_str())),
        Err(_) => RocResult::err(()),
    }
}

#[no_mangle]
pub extern "C" fn roc_fx_stdinLine() -> RocResult<RocStr, ()> {
    use std::io::BufRead;

    let stdin = std::io::stdin();
    if let Some(Ok(line)) = stdin.lock().lines().next() {
        RocResult::ok(RocStr::from(line.as_str()))
    } else {
        RocResult::err(())
    }
}

#[no_mangle]
pub extern "C" fn roc_fx_stdoutLine(line: &RocStr) {
    let string = line.as_str();
    println!("{}", string);
    std::io::stdout().flush().unwrap();
}

#[no_mangle]
pub extern "C" fn roc_fx_stdoutWrite(text: &RocStr) {
    let string = text.as_str();
    print!("{}", string);
    std::io::stdout().flush().unwrap();
}

#[no_mangle]
pub extern "C" fn roc_fx_stderrLine(line: &RocStr) {
    let string = line.as_str();
    eprintln!("{}", string);
}

#[no_mangle]
pub extern "C" fn roc_fx_stderrWrite(text: &RocStr) {
    let string = text.as_str();
    eprint!("{}", string);
    std::io::stderr().flush().unwrap();
}

// #[no_mangle]
// pub extern "C" fn roc_fx_fileWriteUtf8(
//     roc_path: &RocList<u8>,
//     roc_string: &RocStr,
//     // ) -> RocResult<(), WriteErr> {
// ) -> (u8, u8) {
//     let _ = write_slice(roc_path, roc_string.as_str().as_bytes());

//     (255, 255)
// }

// #[no_mangle]
// pub extern "C" fn roc_fx_fileWriteUtf8(roc_path: &RocList<u8>, roc_string: &RocStr) -> Fail {
//     write_slice2(roc_path, roc_string.as_str().as_bytes())
// }
#[no_mangle]
pub extern "C" fn roc_fx_fileWriteUtf8(
    roc_path: &RocList<u8>,
    roc_str: &RocStr,
) -> RocResult<(), WriteErr> {
    write_slice(roc_path, roc_str.as_str().as_bytes())
}

#[no_mangle]
pub extern "C" fn roc_fx_fileWriteBytes(
    roc_path: &RocList<u8>,
    roc_bytes: &RocList<u8>,
) -> RocResult<(), WriteErr> {
    write_slice(roc_path, roc_bytes.as_slice())
}

fn write_slice(roc_path: &RocList<u8>, bytes: &[u8]) -> RocResult<(), WriteErr> {
    match File::create(path_from_roc_path(roc_path)) {
        Ok(mut file) => match file.write_all(bytes) {
            Ok(()) => RocResult::ok(()),
            Err(err) => RocResult::err(toRocWriteError(err)),
        },
        Err(err) => RocResult::err(toRocWriteError(err)),
    }
}

#[cfg(target_family = "unix")]
fn path_from_roc_path(bytes: &RocList<u8>) -> Cow<'_, Path> {
    use std::os::unix::ffi::OsStrExt;
    let os_str = OsStr::from_bytes(bytes.as_slice());
    Cow::Borrowed(Path::new(os_str))
}

#[cfg(target_family = "windows")]
fn path_from_roc_path(bytes: &RocList<u8>) -> Cow<'_, Path> {
    use std::os::windows::ffi::OsStringExt;

    let bytes = bytes.as_slice();
    assert_eq!(bytes.len() % 2, 0);
    let characters: &[u16] =
        unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast(), bytes.len() / 2) };

    let os_string = std::ffi::OsString::from_wide(characters);

    Cow::Owned(std::path::PathBuf::from(os_string))
}

#[no_mangle]
pub extern "C" fn roc_fx_fileReadBytes(roc_path: &RocList<u8>) -> RocResult<RocList<u8>, ReadErr> {
    use std::io::Read;

    let mut bytes = Vec::new();

    match File::open(path_from_roc_path(roc_path)) {
        Ok(mut file) => match file.read_to_end(&mut bytes) {
            Ok(_bytes_read) => RocResult::ok(RocList::from(bytes.as_slice())),
            Err(err) => RocResult::err(toRocReadError(err)),
        },
        Err(err) => RocResult::err(toRocReadError(err)),
    }
}

#[no_mangle]
pub extern "C" fn roc_fx_fileDelete(roc_path: &RocList<u8>) -> RocResult<(), ReadErr> {
    match std::fs::remove_file(path_from_roc_path(roc_path)) {
        Ok(()) => RocResult::ok(()),
        Err(err) => RocResult::err(toRocReadError(err)),
    }
}

#[no_mangle]
pub extern "C" fn roc_fx_cwd() -> RocList<u8> {
    // TODO instead, call getcwd on UNIX and GetCurrentDirectory on Windows
    match std::env::current_dir() {
        Ok(path_buf) => os_str_to_roc_path(path_buf.into_os_string().as_os_str()),
        Err(_) => {
            // Default to empty path
            RocList::empty()
        }
    }
}

#[no_mangle]
pub extern "C" fn roc_fx_dirList(
    // TODO: this RocResult should use Dir.WriteErr - but right now it's File.WriteErr
    // because glue doesn't have Dir.WriteErr yet.
    roc_path: &RocList<u8>,
) -> RocResult<RocList<RocList<u8>>, WriteErr> {
    println!("Dir.list...");
    match std::fs::read_dir(path_from_roc_path(roc_path)) {
        Ok(dir_entries) => RocResult::ok(
            dir_entries
                .map(|opt_dir_entry| match opt_dir_entry {
                    Ok(entry) => os_str_to_roc_path(entry.path().into_os_string().as_os_str()),
                    Err(_) => {
                        todo!("handle dir_entry path didn't resolve")
                    }
                })
                .collect::<RocList<RocList<u8>>>(),
        ),
        Err(err) => RocResult::err(toRocWriteError(err)),
    }
}

#[cfg(target_family = "unix")]
fn os_str_to_roc_path(os_str: &OsStr) -> RocList<u8> {
    use std::os::unix::ffi::OsStrExt;

    RocList::from(os_str.as_bytes())
}

#[cfg(target_family = "windows")]
fn os_str_to_roc_path(os_str: &OsStr) -> RocList<u8> {
    use std::os::windows::ffi::OsStrExt;

    let bytes: Vec<_> = os_str.encode_wide().flat_map(|c| c.to_be_bytes()).collect();

    RocList::from(bytes.as_slice())
}

#[no_mangle]
pub extern "C" fn roc_fx_sendRequest(roc_request: &glue::Request) -> glue::Response {
    let mut builder = reqwest::blocking::ClientBuilder::new();

    if roc_request.timeout.discriminant() == glue::discriminant_TimeoutConfig::TimeoutMilliseconds {
        let ms: &u64 = unsafe { roc_request.timeout.as_TimeoutMilliseconds() };
        builder = builder.timeout(Duration::from_millis(*ms));
    }

    let client = match builder.build() {
        Ok(c) => c,
        Err(_) => {
            return glue::Response::NetworkError; // TLS backend cannot be initialized
        }
    };

    let method = match roc_request.method {
        glue::Method::Connect => reqwest::Method::CONNECT,
        glue::Method::Delete => reqwest::Method::DELETE,
        glue::Method::Get => reqwest::Method::GET,
        glue::Method::Head => reqwest::Method::HEAD,
        glue::Method::Options => reqwest::Method::OPTIONS,
        glue::Method::Patch => reqwest::Method::PATCH,
        glue::Method::Post => reqwest::Method::POST,
        glue::Method::Put => reqwest::Method::PUT,
        glue::Method::Trace => reqwest::Method::TRACE,
    };

    let url = roc_request.url.as_str();

    let mut req_builder = client.request(method, url);
    for header in roc_request.headers.iter() {
        let (name, value) = unsafe { header.as_Header() };
        req_builder = req_builder.header(name.as_str(), value.as_str());
    }
    if roc_request.body.discriminant() == glue::discriminant_Body::Body {
        let (mime_type_tag, body_byte_list) = unsafe { roc_request.body.as_Body() };
        let mime_type_str: &RocStr = unsafe { mime_type_tag.as_MimeType() };

        req_builder = req_builder.header("Content-Type", mime_type_str.as_str());
        req_builder = req_builder.body(body_byte_list.as_slice().to_vec());
    }

    let request = match req_builder.build() {
        Ok(req) => req,
        Err(err) => {
            return glue::Response::BadRequest(RocStr::from(err.to_string().as_str()));
        }
    };

    match client.execute(request) {
        Ok(response) => {
            let status = response.status();
            let status_str = status.canonical_reason().unwrap_or_else(|| status.as_str());

            let headers_iter = response.headers().iter().map(|(name, value)| {
                glue::Header::Header(
                    RocStr::from(name.as_str()),
                    RocStr::from(value.to_str().unwrap_or_default()),
                )
            });

            let metadata = Metadata {
                headers: RocList::from_iter(headers_iter),
                statusText: RocStr::from(status_str),
                url: RocStr::from(url),
                statusCode: status.as_u16(),
            };

            let bytes = response.bytes().unwrap_or_default();
            let body: RocList<u8> = RocList::from_iter(bytes.into_iter());

            if status.is_success() {
                glue::Response::GoodStatus(metadata, body)
            } else {
                glue::Response::BadStatus(metadata, body)
            }
        }
        Err(err) => {
            if err.is_timeout() {
                glue::Response::Timeout
            } else if err.is_request() {
                glue::Response::BadRequest(RocStr::from(err.to_string().as_str()))
            } else {
                glue::Response::NetworkError
            }
        }
    }
}

fn toRocWriteError(err: std::io::Error) -> file_glue::WriteErr {
    match err.kind() {
        std::io::ErrorKind::NotFound => file_glue::WriteErr::NotFound,
        std::io::ErrorKind::AlreadyExists => file_glue::WriteErr::AlreadyExists,
        std::io::ErrorKind::Interrupted => file_glue::WriteErr::Interrupted,
        std::io::ErrorKind::OutOfMemory => file_glue::WriteErr::OutOfMemory,
        std::io::ErrorKind::PermissionDenied => file_glue::WriteErr::PermissionDenied,
        std::io::ErrorKind::TimedOut => file_glue::WriteErr::TimedOut,
        // TODO investigate support the following IO errors may need to update API
        std::io::ErrorKind::WriteZero => file_glue::WriteErr::WriteZero,
        _ => file_glue::WriteErr::Unsupported,
        // TODO investigate support the following IO errors
        // std::io::ErrorKind::FileTooLarge <- unstable language feature
        // std::io::ErrorKind::ExecutableFileBusy <- unstable language feature
        // std::io::ErrorKind::FilesystemQuotaExceeded <- unstable language feature
        // std::io::ErrorKind::InvalidFilename <- unstable language feature
        // std::io::ErrorKind::ResourceBusy <- unstable language feature
        // std::io::ErrorKind::ReadOnlyFilesystem <- unstable language feature
        // std::io::ErrorKind::TooManyLinks <- unstable language feature
        // std::io::ErrorKind::StaleNetworkFileHandle <- unstable language feature
        // std::io::ErrorKind::StorageFull <- unstable language feature
    }
}

fn toRocReadError(err: std::io::Error) -> file_glue::ReadErr {
    match err.kind() {
        std::io::ErrorKind::Interrupted => file_glue::ReadErr::Interrupted,
        std::io::ErrorKind::NotFound => file_glue::ReadErr::NotFound,
        std::io::ErrorKind::OutOfMemory => file_glue::ReadErr::OutOfMemory,
        std::io::ErrorKind::PermissionDenied => file_glue::ReadErr::PermissionDenied,
        std::io::ErrorKind::TimedOut => file_glue::ReadErr::TimedOut,
        // TODO investigate support the following IO errors may need to update API
        // std::io::ErrorKind:: => file_glue::ReadErr::TooManyHardlinks,
        // std::io::ErrorKind:: => file_glue::ReadErr::TooManySymlinks,
        // std::io::ErrorKind:: => file_glue::ReadErr::Unrecognized,
        // std::io::ErrorKind::StaleNetworkFileHandle <- unstable language feature
        // std::io::ErrorKind::InvalidFilename <- unstable language feature
        _ => file_glue::ReadErr::Unsupported,
    }
}
