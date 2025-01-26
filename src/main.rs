use std::{io, thread, env, fs};
use std::process::{exit, Command, Stdio};
use std::io::{ErrorKind, IoSlice, Read, Write, Error, BufWriter};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::fs::FileTypeExt;
use native_dialog::{MessageDialog};
use sha2::Digest;
use base64ct::{Base64, Encoding};
use log::*;

const SSH_AGENTC_REQUEST_IDENTITIES : u8 = 11;
const SSH_AGENTC_SIGN_REQUEST : u8 = 13;

const SSH_AGENT_FAILURE : u8 = 5;
//const SSH_AGENT_SUCCESS : u8 = 6;
const SSH_AGENT_IDENTITIES_ANSWER : u8 = 12;

#[derive(Clone, Debug)]
struct Config {
    always_confirm: bool,
    subagent_paths: Vec<String>,
}

fn server_thread(listener: UnixListener, config: Config) -> io::Result<()> {
    for client in listener.incoming() {
        debug!("New client connection");
        let config_copy = config.clone();
        thread::spawn(move || connection_thread(client?, config_copy));
    }
    Ok(())
}

fn connection_thread(client: UnixStream, config: Config) -> io::Result<()> {
    let mut subagents = Vec::new();

    for path in &config.subagent_paths {
        match UnixStream::connect(path) {
            Ok(agent) => {
                debug!("Connection established with {:?}", path);
                subagents.push(agent)
            },
            Err(err) => eprintln!("failed to connect to {} {}", path, err),
        }
    }

    if subagents.is_empty() {
        return Err(Error::new(ErrorKind::Other, "no sub-agents connections to work with"));
    }

    loop {
        let request = read_packet(&client)?;
        debug!("Client request:\n{}", hexdump(&request));
        let mut result = vec![SSH_AGENT_FAILURE];

        if request[0] == SSH_AGENTC_REQUEST_IDENTITIES {
            for subagent in &subagents {
                debug!("Forwarding request to {:?}", subagent);
                write_packet(&subagent, &request)?;
                let response = read_packet(&subagent)?;
                debug!("Response:\n{}", hexdump(&response));
                result = merge_identities(result, response)?;
            }
            write_packet(&client, &result)?;
            if subagents.len() > 1 {
                debug!("Sending merged response to client:\n{}", hexdump(&result));
            } else {
                debug!("Sending last response to client");
            }
            continue;
        }

        // confirm sign request
        if config.always_confirm && request[0] == SSH_AGENTC_SIGN_REQUEST {
            let keyblob = read_bstring(&request[1..])?;
            if !confirm_usage(&keyblob) {
                debug!("Usage denied! Sending failure response to client");
                write_packet(&client, &vec![SSH_AGENT_FAILURE])?;
                continue;
            }
        }
        // for all requests other than identities request just return first successful answer
        for subagent in &subagents {
            debug!("Forwarding request to {:?}", subagent.peer_addr()?);
            write_packet(&subagent, &request)?;
            let response = read_packet(&subagent)?;
            debug!("Received response:\n{}", hexdump(&response));
            if response[0] != SSH_AGENT_FAILURE {
                result = response;
                break;
            }
        }
        debug!("Sending last response to client");
        write_packet(&client, &result)?;
    }
}

fn merge_identities(i1 : Vec<u8>, i2 : Vec<u8>) -> io::Result<Vec<u8>> {
    if i1.len() < 5 || i1[0] != SSH_AGENT_IDENTITIES_ANSWER {
        return Ok(i2)
    }
    if i2.len() < 5 || i2[0] != SSH_AGENT_IDENTITIES_ANSWER {
        return Ok(i1)
    }
    let i1cnt = read_u32(&i1[1..5])?;
    let i2cnt = read_u32(&i2[1..5])?;
    let mut result = Vec::with_capacity(i1.len() + i2.len() - 5);
    result.push(SSH_AGENT_IDENTITIES_ANSWER);
    result.extend_from_slice(&u32::to_be_bytes(i1cnt + i2cnt));
    result.extend_from_slice(&i1[5..]);
    result.extend_from_slice(&i2[5..]);
    Ok(result)
}

fn confirm_usage(keyblob : &[u8]) -> bool {
    let fingerprint = fingerprint(&keyblob);
    let text = format!("Do you confirm sign request with the following key?\nSHA256:{}", fingerprint);
    MessageDialog::new()
        .set_title("SSH Agent Request Confirmation")
        .set_text(text.as_str())
        .show_confirm().unwrap_or_else(|_| false)
}

fn fingerprint(keyblob: &[u8]) -> String {
    let digest = sha2::Sha256::digest(keyblob);
    let mut enc_buf = [0u8; 64];
    Base64::encode(digest.as_slice(), &mut enc_buf).unwrap().to_string()
}

fn read_u32(bytes: &[u8]) -> io::Result<u32> {
    if bytes.len() < 4 {
        return Err(Error::new(ErrorKind::InvalidInput, "not enough bytes"))
    }
    Ok(u32::from_be_bytes(bytes[0..4].try_into().unwrap()))
}

fn read_bstring(bytes: &[u8]) -> io::Result<&[u8]> {
    let len = read_u32(bytes)? as usize;
    if bytes.len() < 4 + len {
        return Err(Error::new(ErrorKind::InvalidInput, "not enough bytes"))
    }
    Ok(&bytes[4..(4 + len)])
}

fn read_packet(mut stream: &UnixStream) -> io::Result<Vec<u8>> {
    let mut lenbuf = [0u8; 4];
    stream.read_exact(&mut lenbuf)?;
    let len: usize = u32::from_be_bytes(lenbuf) as usize;
    if len == 0 || len > 16 * 1024 {
        return Err(Error::new(ErrorKind::InvalidData,"Invalid packet size"));
    }
    let mut packet = vec![0u8; len];
    stream.read_exact(&mut packet)?;
    Ok(packet)
}

fn write_packet(mut stream: &UnixStream, packet: &[u8]) -> io::Result<usize> {
    let lenbuf = u32::to_be_bytes(packet.len() as u32);
    stream.write_vectored(&[IoSlice::new(&lenbuf), IoSlice::new(&packet)])
}

fn hexdump(v : &[u8]) -> String {
    let mut p = kex::Printer::default_fmt_with(BufWriter::new(Vec::new()), 0);
    p.push(v).unwrap();
    String::from_utf8(p.finish().into_inner().unwrap()).unwrap()
}

fn usage(rc : i32) {
    let current_exe = env::current_exe().unwrap();
    let program_name = current_exe.file_name().unwrap();
    eprintln!("Usage: {} [-p] [ADDITIONAL_SUBAGENT_PATH]...\n", program_name.to_str().unwrap());
    eprintln!("  -p, --permissive    do not show confirmation dialog");
    eprintln!("                      only useful when additional subagents are used");
    eprintln!("  -h, --help          this usage help");
    eprintln!("");
    eprintln!("Always proxies the current agent pointed by SSH_AUTH_SOCK environment variable.");
    eprintln!("You can specify additional agents that should be queried in case when you want");
    eprintln!("to use keys from multiple sources.");
    eprintln!("In case multiple agents are used all client requests (beside identities request)");
    eprintln!("are processed sequentially until receiving first successfull response from sub agent.");
    exit(rc);
}

fn main() {
    env_logger::init();

    let mut config = Config {
        always_confirm: true,
        subagent_paths: vec![],
    };

    for arg in env::args().skip(1) {
        if arg == "-p" || arg == "--permissive" {
            config.always_confirm = false;
        } else if arg == "-h" || arg == "--help" {
            usage(0);
        } else if arg.starts_with("-") {
            eprintln!("Unknown flag: {}", arg);
            usage(1);
        } else {
            match fs::metadata(&arg) {
                Ok(metadata) => {
                    if metadata.file_type().is_socket() {
                        config.subagent_paths.push(arg);
                    } else {
                        eprintln!("Given path is not unix socket: {}", arg);
                        exit(1);
                    }
                }
                Err(_) => {
                    eprintln!("Given path is not unix socket: {}", arg);
                    exit(1);
                }
            }
        }
    }

    let prev_auth_sock : String;
    match env::var("SSH_AUTH_SOCK") {
        Ok(sock) => {
            prev_auth_sock = sock.to_string();
            config.subagent_paths.push(sock.to_string())
        },
        Err(_) => {
            eprintln!("SSH_AUTH_SOCK environment variable not found");
            exit(1);
        }
    }

    let our_sock_name = env::temp_dir().join(format!("ssh-agentex-{}.sock", std::process::id()));
    let listener = UnixListener::bind(&our_sock_name).expect("failed to bind socket");

    thread::spawn(move || server_thread(listener, config));

    env::set_var("SSH_AUTH_SOCK", &our_sock_name);
    eprintln!("SSH_AUTH_SOCK={:?}", our_sock_name);
    let shell_name = env::var_os("SHELL").unwrap_or_else(|| "bash".into());
    let mut shell = Command::new(shell_name)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Cannot start shell!");

    shell.wait().expect("");

    eprintln!("SSH_AUTH_SOCK={}", prev_auth_sock);
    if let Err(err) = fs::remove_file(&our_sock_name) {
        eprintln!("Cannot remove {:?}: {}", our_sock_name, err);
    }
}
